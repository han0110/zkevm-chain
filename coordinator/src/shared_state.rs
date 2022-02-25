use std::cmp;
use std::collections::HashMap;
use std::env::var;
use std::sync::Arc;

use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::task::spawn;

use ethers_core::abi::Abi;
use ethers_core::abi::AbiEncode;
use ethers_core::abi::AbiParser;
use ethers_core::abi::RawLog;
use ethers_core::abi::Tokenizable;
use ethers_core::types::{
    Address, Block, Bytes, Filter, Log, Transaction, TxpoolStatus, ValueOrArray, H256, U256, U64,
};
use ethers_core::utils::keccak256;
use ethers_signers::LocalWallet;
use ethers_signers::Signer;

use hyper::client::HttpConnector;
use hyper::Uri;

use crate::structs::*;
use crate::utils::*;

pub struct RoState {
    pub leader_node: Uri,
    pub l1_node: Uri,
    pub l1_bridge_addr: Address,
    pub l1_bridge_abi: Abi,
    pub block_beacon_topic: H256,
    pub block_finalized_topic: H256,
    pub message_beacon_topic: H256,
    pub http_client: hyper::Client<HttpConnector>,
    pub l1_wallet: LocalWallet,
    pub l2_wallet: LocalWallet,
}

pub struct RwState {
    pub chain_state: ForkchoiceStateV1,
    pub nodes: Vec<Uri>,
    pub prover_requests: HashMap<U64, Option<Proofs>>,
    pub pending_proofs: u32,
    pub last_sync_block: U64,
    pub l1_message_queue: Vec<L1MessageBeacon>,
}

#[derive(Clone)]
pub struct SharedState {
    pub ro: Arc<RoState>,
    pub rw: Arc<Mutex<RwState>>,
}

impl SharedState {
    pub fn new(
        leader_url: Uri,
        l1_url: Uri,
        l1_bridge: Address,
        l1_wallet: LocalWallet,
        l2_wallet: LocalWallet,
    ) -> SharedState {
        let abi = AbiParser::default()
            .parse(&[
                "event BlockSubmitted()",
                "event BlockFinalized(bytes32 blockHash)",
                "event L1MessageSent(address from, address to, uint256 value, uint256 fee, bytes data)",
                "function submitBlock(bytes)",
                "function finalizeBlock(bytes32 blockHash, bytes witness, bytes proof)",
            ])
            .expect("parse abi");

        let beacon_topic = abi.event("BlockSubmitted").unwrap().signature();
        let block_finalized_topic = abi.event("BlockFinalized").unwrap().signature();
        let message_topic = abi.event("L1MessageSent").unwrap().signature();

        Self {
            ro: Arc::new(RoState {
                leader_node: leader_url,
                l1_node: l1_url,
                l1_bridge_addr: l1_bridge,
                l1_bridge_abi: abi,
                block_beacon_topic: beacon_topic,
                block_finalized_topic,
                message_beacon_topic: message_topic,
                http_client: hyper::Client::new(),
                l1_wallet,
                l2_wallet,
            }),
            rw: Arc::new(Mutex::new(RwState {
                chain_state: ForkchoiceStateV1 {
                    head_block_hash: H256::zero(),
                    safe_block_hash: H256::zero(),
                    finalized_block_hash: H256::zero(),
                },
                nodes: Vec::new(),
                prover_requests: HashMap::new(),
                pending_proofs: 0,
                last_sync_block: U64::zero(),
                l1_message_queue: Vec::new(),
            })),
        }
    }

    pub async fn from_env() -> SharedState {
        let l2_url = var("L2_RPC_URL")
            .expect("L2_RPC_URL env var")
            .parse::<Uri>()
            .expect("Uri from L2_RPC_URL");
        let l1_url = var("L1_RPC_URL")
            .expect("L1_RPC_URL env var")
            .parse::<Uri>()
            .expect("Uri from L1_RPC_URL");
        let l1_bridge = var("L1_BRIDGE")
            .expect("L1_BRIDGE env var")
            .parse::<Address>()
            .expect("Address from L1_BRIDGE");

        let chain_id: U64 = jsonrpc_request(&l1_url, "eth_chainId", ())
            .await
            .expect("chain id");
        let l1_wallet = var("L1_PRIV")
            .expect("L1_PRIV env var")
            .parse::<LocalWallet>()
            .expect("LocalWallet from L1_PRIV")
            .with_chain_id(chain_id.as_u64());

        let chain_id: U64 = jsonrpc_request(&l2_url, "eth_chainId", ())
            .await
            .expect("chain id");
        // TODO: support different keys
        let l2_wallet = var("L1_PRIV")
            .expect("L1_PRIV env var")
            .parse::<LocalWallet>()
            .expect("LocalWallet from L1_PRIV")
            .with_chain_id(chain_id.as_u64());

        Self::new(l2_url, l1_url, l1_bridge, l1_wallet, l2_wallet)
    }

    pub async fn init(&self) {
        if !self.rw.lock().await.chain_state.head_block_hash.is_zero() {
            panic!("init");
        }

        let genesis: Block<H256> = crate::timeout!(
            5000,
            jsonrpc_request(&self.ro.leader_node, "eth_getBlockByNumber", ("0x0", false))
                .await
                .unwrap()
        );
        let h = genesis.hash.unwrap();
        log::info!("init with genesis: {:?}", h);

        let chain_state = &mut self.rw.lock().await.chain_state;
        chain_state.head_block_hash = h;
        chain_state.safe_block_hash = h;
        chain_state.finalized_block_hash = h;
    }

    pub async fn sync(&self) {
        // sync events
        let latest_block: U64 = jsonrpc_request_client(
            &self.ro.http_client,
            &self.ro.l1_node,
            "eth_blockNumber",
            (),
        )
        .await
        .expect("eth_blockNumber");
        let mut from: U64 = self.rw.lock().await.last_sync_block + 1;
        let mut filter = Filter::new()
            .address(ValueOrArray::Value(self.ro.l1_bridge_addr))
            .topic0(ValueOrArray::Array(vec![
                self.ro.block_beacon_topic,
                self.ro.block_finalized_topic,
                self.ro.message_beacon_topic,
            ]));

        while from <= latest_block {
            // TODO: increase or decrease request range depending on fetch success
            let to = cmp::min(from + 1u64, latest_block);
            log::info!("fetching l1 logs from={} to={}", from, to);
            filter = filter.from_block(from).to_block(to);

            let logs: Vec<Log> = jsonrpc_request_client(
                &self.ro.http_client,
                &self.ro.l1_node,
                "eth_getLogs",
                [&filter],
            )
            .await
            .expect("");

            for log in logs {
                let topic = log.topics[0];

                if topic == self.ro.block_beacon_topic {
                    let tx_hash = log.transaction_hash.expect("log txhash");
                    let tx: Transaction = jsonrpc_request_client(
                        &self.ro.http_client,
                        &self.ro.l1_node,
                        "eth_getTransactionByHash",
                        [tx_hash],
                    )
                    .await
                    .expect("tx");

                    let tx_data = tx.input.as_ref();

                    // TODO: handle the case if len < 68
                    let len = U256::from(&tx_data[36..68]).as_usize();
                    let start = 68;
                    let end = start + len;
                    if end > tx_data.len() {
                        log::warn!("TODO: zeropad block data");
                    }
                    let block_hash = H256::from(keccak256(&tx_data[start..end]));
                    log::info!("BlockSubmitted: {:?} via {:?}", block_hash, tx_hash);

                    let resp: Result<serde_json::Value, String> = jsonrpc_request_client(
                        &self.ro.http_client,
                        &self.ro.leader_node,
                        "eth_getHeaderByHash",
                        [block_hash],
                    )
                    .await;

                    if resp.is_err() {
                        log::error!(
                            "TODO: block not found {} {}",
                            block_hash,
                            resp.err().unwrap()
                        );
                    }

                    self.rw.lock().await.chain_state.safe_block_hash = block_hash;
                    continue;
                }

                if topic == self.ro.block_finalized_topic {
                    let block_hash = H256::from_slice(log.data.as_ref());
                    log::info!(
                        "BlockFinalized: {:?} via {:?}",
                        block_hash,
                        log.transaction_hash
                    );

                    self.rw.lock().await.chain_state.finalized_block_hash = block_hash;
                    continue;
                }

                if topic == self.ro.message_beacon_topic {
                    // TODO: this is really ugly. consider finding a alternative
                    let evt = self.ro.l1_bridge_abi.event("L1MessageSent").unwrap();
                    let evt = evt
                        .parse_log(RawLog::from((log.topics, log.data.to_vec())))
                        .unwrap();

                    let from = evt.params[0].value.to_owned().into_address().unwrap();
                    let to = evt.params[1].value.to_owned().into_address().unwrap();
                    let value = evt.params[2].value.to_owned().into_uint().unwrap();
                    let fee = evt.params[3].value.to_owned().into_uint().unwrap();
                    let calldata = evt.params[4].value.to_owned().into_bytes().unwrap();

                    log::info!(
                        "L1MessageSent: from={:?} to={:?} value={} fee={} data={:x?}",
                        from,
                        to,
                        value,
                        fee,
                        calldata
                    );

                    let beacon = L1MessageBeacon {
                        from,
                        to,
                        value,
                        fee,
                        calldata,
                        timestamp: 0,
                    };
                    self.rw.lock().await.l1_message_queue.push(beacon);
                    continue;
                }
            }

            from = to + 1u64;
        }

        self.rw.lock().await.last_sync_block = latest_block;
    }

    pub async fn mine(&self) {
        {
            // check l1 > l2 message queue
            // TODO: state mgmt for messages, processing should be done in a different step
            // and always go through the l2 bridge
            let mut rw = self.rw.lock().await;
            let len = rw.l1_message_queue.len();

            if len > 0 {
                let todo: Vec<L1MessageBeacon> = rw.l1_message_queue.drain(0..1).collect();
                drop(rw);

                for msg in todo {
                    log::info!("processing: {:?}", msg);
                    self.transaction_to_l2(msg.to, msg.value, msg.calldata)
                        .await;
                }
            }
        }

        // check if we can mine a block
        let resp: TxpoolStatus = crate::timeout!(
            5000,
            jsonrpc_request_client(
                &self.ro.http_client,
                &self.ro.leader_node,
                "txpool_status",
                ()
            )
            .await
            .unwrap()
        );
        let pending_txs = resp.pending.as_u64();

        if pending_txs > 0 {
            log::info!(
                "submitting mining request to leader node - pending: {}",
                pending_txs
            );

            // kick miner
            let _resp: Option<bool> = crate::timeout!(
                5000,
                jsonrpc_request_client(
                    &self.ro.http_client,
                    &self.ro.leader_node,
                    "miner_start",
                    [1u64]
                )
                .await
                .unwrap_or_default()
            );
        }
        // stop again
        let _resp: Option<bool> = crate::timeout!(
            5000,
            jsonrpc_request_client(&self.ro.http_client, &self.ro.leader_node, "miner_stop", ())
                .await
                .unwrap_or_default()
        );

        let head_hash = get_chain_head_hash(&self.ro.http_client, &self.ro.leader_node).await;
        self.rw.lock().await.chain_state.head_block_hash = head_hash;
    }

    pub async fn submit_blocks(&self) {
        // block submission
        let safe_hash = self.rw.lock().await.chain_state.safe_block_hash;
        let head_hash = self.rw.lock().await.chain_state.head_block_hash;
        if safe_hash != head_hash {
            // find all the blocks since `safe_hash`
            let blocks = get_blocks_between(
                &self.ro.http_client,
                &self.ro.leader_node,
                &safe_hash,
                &head_hash,
            )
            .await;

            log::info!("blocks to be submitted: {:?}", blocks.len());
            for block in blocks.iter().rev() {
                log::info!("submit_block: {}", format_block(block));
                {
                    let block_data: Bytes = jsonrpc_request_client(
                        &self.ro.http_client,
                        &self.ro.leader_node,
                        "debug_getHeaderRlp",
                        [block.number.unwrap().as_u64()],
                    )
                    .await
                    .expect("block");

                    let calldata = self
                        .ro
                        .l1_bridge_abi
                        .function("submitBlock")
                        .unwrap()
                        .encode_input(&[block_data.into_token()])
                        .expect("calldata");

                    self.transaction_to_l1(self.ro.l1_bridge_addr, U256::zero(), calldata)
                        .await;
                }
            }
        }
    }

    pub async fn finalize_blocks(&self) {
        // block finalization
        let safe_hash = self.rw.lock().await.chain_state.safe_block_hash;
        let final_hash = self.rw.lock().await.chain_state.finalized_block_hash;
        if final_hash != safe_hash {
            let blocks = get_blocks_between(
                &self.ro.http_client,
                &self.ro.leader_node,
                &final_hash,
                &safe_hash,
            )
            .await;

            log::info!("blocks for finalization: {:?}", blocks.len());
            for block in blocks.iter().rev() {
                self.finalize_block(block).await;
            }
        }
    }

    pub async fn finalize_block(&self, block: &Block<H256>) {
        log::debug!("TODO finalize_block: {}", format_block(block));

        let k = block.number.unwrap();
        let mut rw = self.rw.lock().await;
        let v = rw.prover_requests.get(&k);

        match v {
            None => {
                const MAX_PENDING_PROOFS: u32 = 1;
                if rw.pending_proofs >= MAX_PENDING_PROOFS {
                    log::debug!("waiting MAX_PENDING_PROOFS");
                    return;
                }
                rw.prover_requests.insert(k, Option::default());
                rw.pending_proofs += 1;
                drop(rw);

                log::info!("requesting proof: {}", format_block(block));

                let ctx = self.clone();
                spawn(async move {
                    // NOTE: if this panics then this loops forever - not a problem once switched to
                    // prover rpc
                    let res = request_proof(k).await;
                    let mut rw = ctx.rw.lock().await;
                    rw.pending_proofs -= 1;
                    match res {
                        Err(_) => rw.prover_requests.remove(&k),
                        Ok(proof) => rw.prover_requests.insert(k, Option::Some(proof)),
                    }
                });
            }
            Some(opt) => match opt {
                None => log::info!("proof not yet computed for: {}", k),
                Some(proof) => {
                    log::info!("found proof: {:?} for {}", proof, format_block(block));

                    let block_hash = block.hash.unwrap();
                    let witness = Bytes::from(block_hash.encode());
                    let mut proof_data = vec![];
                    proof_data.extend_from_slice(proof.evm_proof.as_ref());
                    proof_data.extend_from_slice(proof.state_proof.as_ref());
                    let proof_data = Bytes::from(proof_data);
                    drop(rw);

                    let calldata = self
                        .ro
                        .l1_bridge_abi
                        .function("finalizeBlock")
                        .unwrap()
                        .encode_input(&[
                            block_hash.into_token(),
                            witness.into_token(),
                            proof_data.into_token(),
                        ])
                        .expect("calldata");

                    self.transaction_to_l1(self.ro.l1_bridge_addr, U256::zero(), calldata)
                        .await;
                }
            },
        }
    }

    pub async fn transaction_to_l1(&self, to: Address, value: U256, calldata: Vec<u8>) {
        send_transaction_to_l1(
            &self.ro.http_client,
            &self.ro.l1_node,
            &self.ro.l1_wallet,
            to,
            value,
            calldata,
        )
        .await;
    }

    pub async fn transaction_to_l2(&self, to: Address, value: U256, calldata: Vec<u8>) {
        send_transaction_to_l2(
            &self.ro.http_client,
            &self.ro.leader_node,
            &self.ro.l2_wallet,
            to,
            value,
            calldata,
        )
        .await;
    }
}

pub async fn request_proof(block_num: U64) -> Result<Proofs, String> {
    // TODO: this should be invoked via rpc without waiting for the proof to be computed
    let output = Command::new("./prover_cmd")
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true)
        .env("BLOCK_NUM", block_num.to_string())
        .output();
    let output = output.await.expect("proof");

    match output.status.success() {
        false => {
            log::error!("computing proof for {}", block_num);
            Err("poof".to_string())
        }
        true => {
            let proof: Proofs = serde_json::from_slice(&output.stdout).expect("parse proofs");
            log::debug!("proof for: {} data: {:?}", block_num, proof);
            Ok(proof)
        }
    }
}