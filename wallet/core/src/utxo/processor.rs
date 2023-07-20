use futures::{select, FutureExt};
use kaspa_notify::{
    listener::ListenerId,
    scope::{Scope, UtxosChangedScope, VirtualDaaScoreChangedScope},
};
use kaspa_rpc_core::message::UtxosChangedNotification;
use kaspa_wrpc_client::KaspaRpcClient;
use workflow_core::channel::{Channel, DuplexChannel};
use workflow_core::task::spawn;
use workflow_rpc::client::Ctl;

use crate::imports::*;
use crate::result::Result;
use crate::utxo::{EventConsumer, Events, PendingUtxoEntryReference, UtxoContext, UtxoContextId, UtxoEntryId, UtxoEntryReference};
use kaspa_rpc_core::{notify::connection::ChannelConnection, Notification};
use std::collections::HashMap;

pub struct Inner {
    pending: DashMap<UtxoEntryId, PendingUtxoEntryReference>,
    address_to_utxo_context_map: DashMap<Arc<Address>, Arc<UtxoContext>>,
    event_consumer: Mutex<Option<Arc<dyn EventConsumer>>>,
    current_daa_score: AtomicU64,

    rpc: Arc<DynRpcApi>,
    is_connected: AtomicBool,
    listener_id: Mutex<Option<ListenerId>>,
    task_ctl: DuplexChannel,
    notification_channel: Channel<Notification>,
}

impl Inner {
    pub fn new(rpc: &Arc<DynRpcApi>) -> Self {
        Self {
            pending: DashMap::new(),
            address_to_utxo_context_map: DashMap::new(),
            event_consumer: Mutex::new(None),
            current_daa_score: AtomicU64::new(0),

            rpc: rpc.clone(),
            is_connected: AtomicBool::new(false),
            listener_id: Mutex::new(None),
            task_ctl: DuplexChannel::oneshot(),
            notification_channel: Channel::<Notification>::unbounded(),
        }
    }
}

#[derive(Clone)]
#[wasm_bindgen]
pub struct UtxoProcessor {
    inner: Arc<Inner>,
}

impl UtxoProcessor {
    pub fn new(rpc: &Arc<DynRpcApi>) -> Self {
        UtxoProcessor { inner: Arc::new(Inner::new(rpc)) }
    }

    pub fn rpc(&self) -> &Arc<DynRpcApi> {
        &self.inner.rpc
    }

    pub fn listener_id(&self) -> ListenerId {
        self.inner.listener_id.lock().unwrap().expect("missing listener_id in UtxoProcessor::listener_id()")
    }

    pub fn pending(&self) -> &DashMap<UtxoEntryId, PendingUtxoEntryReference> {
        &self.inner.pending
    }

    pub fn current_daa_score(&self) -> u64 {
        self.inner.current_daa_score.load(Ordering::SeqCst)
    }

    pub async fn clear(&self) -> Result<()> {
        self.inner.address_to_utxo_context_map.clear();
        // TODO - clear processors?
        Ok(())
    }

    pub fn address_to_utxo_context_map(&self) -> &DashMap<Arc<Address>, Arc<UtxoContext>> {
        &self.inner.address_to_utxo_context_map
    }

    pub fn address_to_utxo_context(&self, address: &Address) -> Option<Arc<UtxoContext>> {
        self.inner.address_to_utxo_context_map.get(address).map(|v| v.clone())
    }

    pub async fn register_addresses(&self, addresses: Vec<Arc<Address>>, processor: &Arc<UtxoContext>) -> Result<()> {
        addresses.iter().for_each(|address| {
            self.inner.address_to_utxo_context_map.insert(address.clone(), processor.clone());
        });

        if self.is_connected() {
            if !addresses.is_empty() {
                let addresses = addresses.into_iter().map(|address| (*address).clone()).collect::<Vec<_>>();
                // let listener_id = self.listener_id();
                // log_info!("registering addresses {:?}", addresses);

                let utxos_changed_scope = UtxosChangedScope { addresses };
                self.rpc().start_notify(self.listener_id(), Scope::UtxosChanged(utxos_changed_scope)).await?;
            } else {
                log_info!("registering empty address list!");
            }
        }
        Ok(())
    }

    pub async fn unregister_addresses(&self, addresses: Vec<Arc<Address>>) -> Result<()> {
        addresses.iter().for_each(|address| {
            self.inner.address_to_utxo_context_map.remove(address);
        });

        if self.is_connected() {
            if !addresses.is_empty() {
                let addresses = addresses.into_iter().map(|address| (*address).clone()).collect::<Vec<_>>();
                // log_info!("unregistering addresses {:?}", addresses);
                let utxos_changed_scope = UtxosChangedScope { addresses };
                self.rpc().stop_notify(self.listener_id(), Scope::UtxosChanged(utxos_changed_scope)).await?;
            } else {
                log_info!("unregistering empty address list!");
            }
        }
        Ok(())
    }

    // pub fn register_event_consumer(&self, event_consumer : Arc<dyn EventConsumer>) {
    //     self.inner.event_consumer.lock().unwrap().replace(event_consumer);
    // }

    pub fn event_consumer(&self) -> Option<Arc<dyn EventConsumer>> {
        self.inner.event_consumer.lock().unwrap().clone()
    }

    pub async fn notify(&self, event: Events) -> Result<()> {
        if let Some(event_consumer) = self.event_consumer() {
            event_consumer.notify(event).await?;
        }
        Ok(())
    }

    pub async fn handle_daa_score_change(&self, current_daa_score: u64) -> Result<()> {
        self.inner.current_daa_score.store(current_daa_score, Ordering::SeqCst);
        self.notify(Events::DAAScoreChange(current_daa_score)).await?;
        self.handle_pending(current_daa_score).await?;
        Ok(())
    }

    // pub async fn handle_pending(&self, current_daa_score: u64) -> Result<Vec<Arc<Account>>> {
    pub async fn handle_pending(&self, current_daa_score: u64) -> Result<()> {
        let mature_entries = {
            let mut mature_entries = vec![];
            let pending_entries = &self.inner.pending;
            pending_entries.retain(|_, pending| {
                if pending.is_mature(current_daa_score) {
                    mature_entries.push(pending.clone());
                    false
                } else {
                    true
                }
            });
            mature_entries
        };

        let mut contexts = HashMap::<UtxoContextId, UtxoContext>::default();
        for mature in mature_entries.into_iter() {
            let utxo_context = &mature.utxo_context;
            let entry = mature.entry;
            utxo_context.promote(entry);

            contexts.insert(utxo_context.id(), utxo_context.clone());
        }

        let contexts = contexts.values().cloned().collect::<Vec<_>>();

        for context in contexts.iter() {
            context.update_balance().await?;
        }

        Ok(())
    }

    pub async fn handle_utxo_changed(&self, utxos: UtxosChangedNotification) -> Result<()> {
        // log_info!("utxo changed: {:?}", utxos);
        let added = (*utxos.added).clone().into_iter().filter_map(|entry| entry.address.clone().map(|address| (address, entry)));
        let added = HashMap::group_from(added);
        for (address, entries) in added.into_iter() {
            if let Some(utxo_context) = self.address_to_utxo_context(&address) {
                let entries = entries.into_iter().map(|entry| entry.into()).collect::<Vec<UtxoEntryReference>>();
                utxo_context.handle_utxo_added(entries).await?;
            } else {
                log_error!("receiving UTXO Changed 'added' notification for an unknown address: {}", address);
            }
        }

        let removed = (*utxos.removed).clone().into_iter().filter_map(|entry| entry.address.clone().map(|address| (address, entry)));
        let removed = HashMap::group_from(removed);
        for (address, entries) in removed.into_iter() {
            if let Some(utxo_context) = self.address_to_utxo_context(&address) {
                let entries = entries.into_iter().map(|entry| entry.into()).collect::<Vec<_>>();
                utxo_context.handle_utxo_removed(entries).await?;
            } else {
                log_error!("receiving UTXO Changed 'removed' notification for an unknown address: {}", address);
            }
        }

        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        self.inner.is_connected.load(Ordering::SeqCst)
    }

    pub async fn handle_connect(self: &Arc<Self>) -> Result<()> {
        self.register_notification_listener().await?;
        // self.start_task().await?;
        Ok(())
    }

    pub async fn handle_disconnect(&self) -> Result<()> {
        self.unregister_notification_listener().await?;
        // self.stop_task().await?;
        Ok(())
    }

    async fn register_notification_listener(&self) -> Result<()> {
        let listener_id = self.rpc().register_new_listener(ChannelConnection::new(self.inner.notification_channel.sender.clone()));
        *self.inner.listener_id.lock().unwrap() = Some(listener_id);

        self.rpc().start_notify(listener_id, Scope::VirtualDaaScoreChanged(VirtualDaaScoreChangedScope {})).await?;

        Ok(())
    }

    async fn unregister_notification_listener(&self) -> Result<()> {
        let listener_id = self.inner.listener_id.lock().unwrap().take();
        if let Some(id) = listener_id {
            // we do not need this as we are unregister the entire listener here...
            // self.rpc.stop_notify(id, Scope::VirtualDaaScoreChanged(VirtualDaaScoreChangedScope {})).await?;
            self.rpc().unregister_listener(id).await?;
        }
        Ok(())
    }

    async fn handle_notification(&self, notification: Notification) -> Result<()> {
        //log_info!("handling notification: {:?}", notification);

        match notification {
            Notification::VirtualDaaScoreChanged(virtual_daa_score_changed_notification) => {
                self.handle_daa_score_change(virtual_daa_score_changed_notification.virtual_daa_score).await?;
            }

            Notification::UtxosChanged(utxos_changed_notification) => {
                self.handle_utxo_changed(utxos_changed_notification).await?;
            }

            _ => {
                log_warning!("unknown notification: {:?}", notification);
            }
        }

        Ok(())
    }

    pub async fn start(self: &Arc<Self>, event_consumer: Option<Arc<dyn EventConsumer>>) -> Result<()> {
        *self.inner.event_consumer.lock().unwrap() = event_consumer;

        let this = self.clone();
        // self.rpc().downcast_arc::<KaspaRpcClient>().expect("unable to downcast DynRpcApi to KaspaRpcClient")

        // let rpc :
        // let rpc_ctl_channel = self.rpc().downcast_arc::<Arc<KaspaRpcClient>>().ctl_multiplexer_channel();
        let rpc_ctl_channel = this
            .rpc()
            .clone()
            .downcast_arc::<KaspaRpcClient>()
            .expect("unable to downcast DynRpcApi to KaspaRpcClient")
            .ctl_multiplexer()
            .create_channel();

        let task_ctl_receiver = self.inner.task_ctl.request.receiver.clone();
        let task_ctl_sender = self.inner.task_ctl.response.sender.clone();
        // let multiplexer = self.multiplexer().clone();
        let notification_receiver = self.inner.notification_channel.receiver.clone();

        spawn(async move {
            'outer: loop {
                select! {
                    _ = task_ctl_receiver.recv().fuse() => {
                        break 'outer;
                    },
                    msg = rpc_ctl_channel.receiver.recv().fuse() => {
                        match msg {
                            Ok(msg) => {
                                match msg {
                                    Ctl::Open => {
                                        this.inner.is_connected.store(true, Ordering::SeqCst);
                                        this.handle_connect().await.unwrap_or_else(|err| log_error!("{err}"));
                                    },
                                    Ctl::Close => {
                                        this.inner.is_connected.store(false, Ordering::SeqCst);
                                        this.handle_disconnect().await.unwrap_or_else(|err| log_error!("{err}"));
                                    }
                                }
                            }
                            Err(err) => {
                                log_error!("UtxoProcessor: error while receiving rpc_ctl_channel message: {err}");
                            }
                        }
                    }
                    notification = notification_receiver.recv().fuse() => {
                        match notification {
                            Ok(notification) => {
                                this.handle_notification(notification).await.unwrap_or_else(|err| {
                                    log_error!("error while handling notification: {err}");
                                });
                            }
                            Err(err) => {
                                log_error!("UtxoProcessor: error while receiving notification: {err}");
                            }
                        }
                    },

                }
            }
            this.inner.event_consumer.lock().unwrap().take();
            task_ctl_sender.send(()).await.unwrap();
        });
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        self.inner.task_ctl.signal(()).await.expect("Wallet::stop_task() `signal` error");
        Ok(())
    }
}

#[wasm_bindgen]
impl UtxoProcessor {}