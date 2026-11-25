use pda_relay_protocol::PdaId;
use std::collections::HashMap;
use tokio::sync::{mpsc, RwLock};

pub type ConnectionId = u64;

#[derive(Clone, Debug)]
pub struct RouteEntry {
    pub connection_id: ConnectionId,
    pub tx: mpsc::Sender<Vec<u8>>,
}

#[derive(Debug, Default)]
pub struct RouteTable {
    routes: RwLock<HashMap<PdaId, RouteEntry>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegisterError {
    RouteInUse,
}

impl RouteTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn register(&self, pda_id: PdaId, entry: RouteEntry) -> Result<(), RegisterError> {
        let mut routes = self.routes.write().await;
        if routes
            .get(&pda_id)
            .is_some_and(|current| !current.tx.is_closed())
        {
            return Err(RegisterError::RouteInUse);
        }
        routes.insert(pda_id, entry);
        Ok(())
    }

    pub async fn lookup(&self, pda_id: &PdaId) -> Option<RouteEntry> {
        self.routes.read().await.get(pda_id).cloned()
    }

    pub async fn remove_if_current(&self, pda_id: &PdaId, connection_id: ConnectionId) {
        let mut routes = self.routes.write().await;
        if routes
            .get(pda_id)
            .is_some_and(|entry| entry.connection_id == connection_id)
        {
            routes.remove(pda_id);
        }
    }

    #[cfg(test)]
    pub async fn route_count(&self) -> usize {
        self.routes.read().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stale_connection_cannot_remove_new_generation() {
        let routes = RouteTable::new();
        let pda = [1; 32];
        let (old_tx, old_rx) = mpsc::channel(1);
        routes
            .register(
                pda,
                RouteEntry {
                    connection_id: 1,
                    tx: old_tx,
                },
            )
            .await
            .unwrap();
        drop(old_rx);
        let (new_tx, _new_rx) = mpsc::channel(1);
        routes
            .register(
                pda,
                RouteEntry {
                    connection_id: 2,
                    tx: new_tx,
                },
            )
            .await
            .unwrap();

        routes.remove_if_current(&pda, 1).await;

        assert_eq!(routes.route_count().await, 1);
        assert_eq!(routes.lookup(&pda).await.unwrap().connection_id, 2);
    }

    #[tokio::test]
    async fn rejects_second_live_route() {
        let routes = RouteTable::new();
        let pda = [2; 32];
        let (first_tx, _first_rx) = mpsc::channel(1);
        let (second_tx, _second_rx) = mpsc::channel(1);
        routes
            .register(
                pda,
                RouteEntry {
                    connection_id: 1,
                    tx: first_tx,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            routes
                .register(
                    pda,
                    RouteEntry {
                        connection_id: 2,
                        tx: second_tx
                    }
                )
                .await,
            Err(RegisterError::RouteInUse)
        );
    }
}
