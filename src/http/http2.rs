//! A minimal HTTP/2 client in Rust written “from scratch” for educational purposes.
//!
//! This client connects via TLS (using rustls) to example.com:443, sends the HTTP/2
//! connection preface and SETTINGS frames, then sends a GET request on stream 1.
//!
//! To run this example, add the following dependencies in your Cargo.toml:
//!
//! ```toml
//! [dependencies]
//! rustls = "0.21"
//! webpki-roots = "0.22"
//! ```
//!
//! Then, run with: `cargo run`
use super::{Error, HttpClient, Request, Response};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

// We'll use rustls for TLS and webpki-roots for trusted certificates.
use rustls::{ClientConnection, StreamOwned};

const PREFACE: &str = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

#[derive(Debug)]
pub struct Http2Client {}

#[derive(Debug)]
struct Frame {
    length: u32,
    frame_type: u8,
    flags: u8,
    stream_id: u32,
    payload: Vec<u8>,
}

impl Frame {
    /// Creates a new frame given its type, flags, stream id and payload.
    fn new(frame_type: u8, flags: u8, stream_id: u32, payload: Vec<u8>) -> Self {
        let length = payload.len() as u32;
        Self {
            length,
            frame_type,
            flags,
            stream_id,
            payload,
        }
    }

    /// Encodes the frame into a byte vector following HTTP/2 framing format.
    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // Length: 24-bit big endian.
        buf.push(((self.length >> 16) & 0xff) as u8);
        buf.push(((self.length >> 8) & 0xff) as u8);
        buf.push((self.length & 0xff) as u8);
        // Type (1 byte) and Flags (1 byte).
        buf.push(self.frame_type);
        buf.push(self.flags);
        // Stream Identifier: 1 reserved bit (0) + 31-bit stream id.
        buf.push(((self.stream_id >> 24) & 0x7f) as u8);
        buf.push(((self.stream_id >> 16) & 0xff) as u8);
        buf.push(((self.stream_id >> 8) & 0xff) as u8);
        buf.push((self.stream_id & 0xff) as u8);
        // Append the payload.
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Prints debugging information about the frame.
    fn debug_print(&self, prefix: &str) {
        println!(
            "{}Frame: type=0x{:02x} ({}), flags=0x{:02x}, stream_id={}, length={}",
            prefix,
            self.frame_type,
            frame_type_to_str(self.frame_type),
            self.flags,
            self.stream_id,
            self.length
        );
        if !self.payload.is_empty() {
            print!("{}Payload ({} bytes):", prefix, self.payload.len());
            for b in &self.payload {
                print!(" {:02x}", b);
            }
            println!();
        } else {
            println!("{}(no payload)", prefix);
        }
    }
}

/// Returns a human‐readable string for a given frame type.
fn frame_type_to_str(frame_type: u8) -> &'static str {
    match frame_type {
        0x0 => "DATA",
        0x1 => "HEADERS",
        0x2 => "PRIORITY",
        0x3 => "RST_STREAM",
        0x4 => "SETTINGS",
        0x5 => "PUSH_PROMISE",
        0x6 => "PING",
        0x7 => "GOAWAY",
        0x8 => "WINDOW_UPDATE",
        0x9 => "CONTINUATION",
        _ => "UNKNOWN",
    }
}

/// Reads an HTTP/2 frame from the given stream.
fn read_frame(stream: &mut dyn Read) -> std::io::Result<Frame> {
    let mut header = [0u8; 9];
    stream.read_exact(&mut header)?;
    let length = ((header[0] as u32) << 16) | ((header[1] as u32) << 8) | (header[2] as u32);
    let frame_type = header[3];
    let flags = header[4];
    let stream_id = ((header[5] as u32 & 0x7f) << 24)
        | ((header[6] as u32) << 16)
        | ((header[7] as u32) << 8)
        | (header[8] as u32);
    let mut payload = vec![0u8; length as usize];
    if length > 0 {
        stream.read_exact(&mut payload)?;
    }
    Ok(Frame {
        length,
        frame_type,
        flags,
        stream_id,
        payload,
    })
}
impl Http2Client {
    pub fn new() -> Self {
        Self {}
    }
}

impl HttpClient for Http2Client {
    fn request(&self, req: Request) -> Result<Response, Error> {
        // --- TLS Setup ---
        // Build a rustls ClientConfig with default safe settings.
        let root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let config = Arc::new(config);

        // The server we wish to connect to.
        let server_addr = req.host() + ":" + req.port().to_string().as_str();

        println!("Connecting to {}", server_addr);
        // Clone server_addr before using it in TcpStream::connect
        let sock = match TcpStream::connect(server_addr.clone()) {
            Ok(sock) => sock,
            Err(e) => {
                println!("Connection failed: {}", e);
                return Err(Error::ConnectionFailed);
            }
        };

        // Convert the domain name to the type expected by rustls.
        // Create a new owned string for server_name to satisfy the 'static lifetime requirement
        let server_name = req.host().try_into().unwrap();
        let conn = ClientConnection::new(config, server_name).unwrap();
        let mut stream = StreamOwned::new(conn, sock);

        // --- HTTP/2 Connection Preface ---
        // The client connection preface must be sent before any frames.
        let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        println!(
            "Sending connection preface:\n{}",
            String::from_utf8_lossy(preface)
        );
        stream
            .write_all(preface)
            .map_err(|e| Error::Other(e.to_string()))?;
        stream.flush().map_err(|e| Error::Other(e.to_string()))?;

        // --- Send Client SETTINGS ---
        // The client must immediately send a SETTINGS frame. Here we send an empty SETTINGS frame.
        let client_settings = Frame::new(0x4, 0x0, 0, Vec::new());
        println!("Sending client SETTINGS frame:");
        client_settings.debug_print("  ");
        stream
            .write_all(&client_settings.encode())
            .map_err(|e| Error::Other(e.to_string()))?;
        stream.flush().map_err(|e| Error::Other(e.to_string()))?;

        // --- Wait for Server SETTINGS ---
        // The server must respond with its SETTINGS. Read frames until we see one.
        println!("Waiting for server SETTINGS frame...");
        loop {
            let frame = read_frame(&mut stream).map_err(|e| Error::Other(e.to_string()))?;
            frame.debug_print("  ");
            if frame.frame_type == 0x4 {
                println!("Received server SETTINGS. Sending SETTINGS ack.");
                // Send SETTINGS ack (same type, but with ACK flag 0x1 set).
                let settings_ack = Frame::new(0x4, 0x1, 0, Vec::new());
                settings_ack.debug_print("  ");
                stream
                    .write_all(&settings_ack.encode())
                    .map_err(|e| Error::Other(e.to_string()))?;
                stream.flush().map_err(|e| Error::Other(e.to_string()))?;
                break;
            }
        }

        // --- Build HPACK Header Block for GET Request ---
        //
        // HTTP/2 requires pseudo-header fields for a request:
        //   :method, :scheme, :path, and :authority.
        //
        // We can use the HPACK static table for most of these:
        //   - ":method: GET" is static table index 2.
        //   - ":scheme: https" is static table index 7.
        //   - ":path: /" is static table index 4.
        //
        // For :authority, we want to use our own value ("example.com").
        // We encode this as a "Literal Header Field without Indexing — Indexed Name"
        // which references the static table entry for ":authority" (index 1).
        //
        // The HPACK encoding is very simple here:
        //   - For indexed header fields, simply output one byte:
        //         0x82 for index 2, 0x87 for index 7, 0x84 for index 4.
        //   - For the literal header field with indexed name:
        //         First, a byte with a 4-bit prefix (the high 4 bits are 0)
        //         and the lower bits encode the index (here, 1).
        //         Then encode the header value as a string literal:
        //         one byte length (MSB=0, no Huffman) followed by the raw bytes.
        let mut header_block = Vec::new();
        // :method: GET -> static table index 2.
        header_block.push(0x82);
        // :scheme: https -> static table index 7.
        header_block.push(0x87);
        // :path: / -> static table index 4.
        header_block.push(0x84);
        // :authority: example.com as a literal header field without indexing.
        // For "Literal Header Field without Indexing — Indexed Name" the first byte
        // has a 4-bit prefix (0000) followed by the index. For index 1, that is just 0x01.
        header_block.push(0x01);
        // Now encode the header value "example.com":
        let authority = b"example.com";
        // First, a length byte (no Huffman; MSB = 0)
        header_block.push(authority.len() as u8);
        // Then the raw bytes.
        header_block.extend_from_slice(authority);

        println!(
            "Constructed HPACK header block ({} bytes):",
            header_block.len()
        );
        print!("  ");
        for b in &header_block {
            print!("{:02x} ", b);
        }
        println!();

        // --- Send HEADERS Frame ---
        // Create a HEADERS frame carrying our header block.
        // Flags: END_HEADERS (0x4) and END_STREAM (0x1) so combined = 0x5.
        // Use stream identifier 1 (the first client-initiated stream).
        let headers_frame = Frame::new(0x1, 0x5, 1, header_block);
        println!("Sending HEADERS frame:");
        headers_frame.debug_print("  ");
        stream
            .write_all(&headers_frame.encode())
            .map_err(|e| Error::Other(e.to_string()))?;
        stream.flush().map_err(|e| Error::Other(e.to_string()))?;

        // --- Read Response Frames ---
        // For this simple example, we just loop reading frames and printing them.
        // We break out when we see END_STREAM on either a HEADERS or DATA frame.
        println!("Reading response frames (CTRL-C to exit if needed)...");
        loop {
            let frame = read_frame(&mut stream).map_err(|e| Error::Other(e.to_string()))?;
            frame.debug_print("  ");
            // Check for END_STREAM flag (0x1) on HEADERS or DATA frames.
            if (frame.frame_type == 0x1 || frame.frame_type == 0x0) && (frame.flags & 0x1 != 0) {
                println!("Received frame with END_STREAM flag. Exiting.");
                break;
            }
        }

        Ok(Response::new(200, Vec::new(), Vec::new()))
    }
}
