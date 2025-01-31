use std::collections::HashMap;
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug)]
struct Connection {
    stream: TcpStream,
    last_used: Instant,
}

#[derive(Clone)]
pub struct ConnectionManager {
    connections: Arc<Mutex<HashMap<String, Connection>>>,
    timeout: Duration,
}

impl ConnectionManager {
    pub fn new(timeout: Duration) -> Self {
        Self {
            connections: Arc::new(Mutex::new(HashMap::new())),
            timeout,
        }
    }

    pub fn get_connection(&self, host: &str, port: u16) -> Option<TcpStream> {
        let key = format!("{}:{}", host, port);
        let mut connections = self.connections.lock().unwrap();

        if let Some(conn) = connections.get_mut(&key) {
            if conn.last_used.elapsed() < self.timeout {
                conn.last_used = Instant::now();
                return Some(conn.stream.try_clone().unwrap());
            }
            connections.remove(&key);
        }
        None
    }

    pub fn store_connection(&self, host: String, port: u16, stream: TcpStream) {
        let key = format!("{}:{}", host, port);
        let connection = Connection {
            stream,
            last_used: Instant::now(),
        };
        self.connections.lock().unwrap().insert(key, connection);
    }

    pub fn cleanup(&self) {
        let mut connections = self.connections.lock().unwrap();
        connections.retain(|_, conn| conn.last_used.elapsed() < self.timeout);
    }
}
