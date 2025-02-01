use bytes::{Bytes, BytesMut};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use super::{HttpClient, Request, Response, Error};

const PREFACE: &str = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

#[derive(Debug, Clone, Copy)]
struct u24([u8; 3]);

#[derive(Debug, Clone, Copy)]
struct u31([u8; 4]);

impl u24 {
    fn from_be_bytes(bytes: [u8; 3]) -> Self {
        Self(bytes)
    }
    
    fn to_be_bytes(&self) -> [u8; 3] {
        self.0
    }
}

impl u31 {
    fn from_be_bytes(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }
    
    fn to_be_bytes(&self) -> [u8; 4] {
        self.0
    }
}

#[derive(Debug)]
pub enum Error {
    Incomplete,
    InvalidFrameType,
    Io(std::io::Error),
    Protocol,
}

#[derive(Debug)]
pub struct Http2Client {
    streams: HashMap<u32, StreamState>,
    next_stream_id: u32,
}

#[derive(Debug)]
struct StreamState {
    headers: Vec<(u8, u8)>,
    data: BytesMut,
    window_size: i32,
}

#[derive(Debug, Clone)]
struct FrameHeader {
    length: u24,
    type_: FrameType,
    flags: u8,
    stream_id: u31,
}

#[derive(Debug, Clone, PartialEq)]
enum FrameType {
    Data,
    Headers,
    Priority,
    RstStream,
    Settings,
    PushPromise,
    Ping,
    GoAway,
    WindowUpdate,
    Continuation,
}

impl FrameHeader {
    fn parse(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < 9 {
            return Err(Error::Incomplete);
        }
        
        let length = u24::from_be_bytes([buf[0], buf[1], buf[2]]);
        let frame_type = match buf[3] {
            0x0 => FrameType::Data,
            0x1 => FrameType::Headers,
            0x2 => FrameType::Priority,
            0x3 => FrameType::RstStream,
            0x4 => FrameType::Settings,
            0x5 => FrameType::PushPromise,
            0x6 => FrameType::Ping,
            0x7 => FrameType::GoAway,
            0x8 => FrameType::WindowUpdate,
            0x9 => FrameType::Continuation,
            _ => return Err(Error::InvalidFrameType),
        };
        
        let flags = buf[4];
        let stream_id = u31::from_be_bytes([
            buf[5], buf[6], buf[7], buf[8]
        ]) & 0x7FFFFFFF;
        
        Ok(Self {
            length,
            type_,
            flags,
            stream_id,
        })
    }
    
    fn serialize(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(9);
        buf.extend_from_slice(&self.length.to_be_bytes());
        buf.put_u8(self.type_ as u8);
        buf.put_u8(self.flags);
        buf.extend_from_slice(&self.stream_id.to_be_bytes());
        buf.freeze()
    }
}

impl Http2Client {
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
            next_stream_id: 1,
        }
    }

    async fn send_preface(&self, stream: &mut tokio::net::TcpStream) -> Result<(), Error> {
        stream.write_all(PREFACE.as_bytes()).await
            .map_err(Error::Io)?;
        Ok(())
    }
}

impl HttpClient for Http2Client {
    async fn request(&self, req: Request) -> Result<Response, Error> {
        // Implementation to be added
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn test_server() -> TcpListener {
        TcpListener::bind("127.0.0.1:0").await.unwrap()
    }

    #[tokio::test]
    async fn test_http2_handshake() {
        let listener = test_server().await;
        let addr = listener.local_addr().unwrap();

        let client = Http2Client::new();
        let mut stream = TcpStream::connect(addr).await.unwrap();

        // Client sends preface
        client.send_preface(&mut stream).await.unwrap();

        // Server reads preface
        let mut buf = [0u8; 24];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, PREFACE.as_bytes());

        // Server sends SETTINGS frame
        let settings_frame = FrameHeader {
            length: 0,
            type_: FrameType::Settings,
            flags: 0,
            stream_id: 0,
        };
        stream.write_all(&settings_frame.serialize()).await.unwrap();

        // Verify client acknowledges settings
        let mut ack_buf = [0u8; 9];
        stream.read_exact(&mut ack_buf).await.unwrap();
        let ack_header = FrameHeader::parse(&ack_buf).unwrap();
        assert_eq!(ack_header.type_, FrameType::Settings);
        assert!(ack_header.flags & 0x01 != 0); // ACK flag
    }
}
