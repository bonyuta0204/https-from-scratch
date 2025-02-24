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
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

// We'll use rustls for TLS and webpki-roots for trusted certificates.
use rustls::{ClientConnection, StreamOwned};

const PREFACE: &str = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

#[derive(Debug)]
pub struct Http2Client {}

#[derive(Debug)]
struct HPackEncoder {}

impl HPackEncoder {
    fn encode(headers: &HashMap<String, String>) -> Vec<u8> {
        let mut results = vec![];
        headers.iter().for_each(|(k, v)| {
            // Pre-defined headers from HPACK static table
            if k == ":method" && v == "GET" {
                results.push(0x82); // Index 2
            } else if k == ":method" && v == "POST" {
                results.push(0x83); // Index 3
            } else if k == ":scheme" && v == "https" {
                results.push(0x87); // Index 7
            } else if k == ":scheme" && v == "http" {
                results.push(0x86); // Index 6
            } else if k == ":path" && v == "/" {
                results.push(0x84); // Index 4
            } else if k == ":authority" {
                // Authority header with indexed name (index 1) + literal value
                results.push(0x01); // Indexed name, index 1
                results.push(v.len() as u8); // Length of value
                results.extend_from_slice(v.as_bytes()); // Value bytes
            } else if k == ":path" {
                // Path header with indexed name (index 4) + literal value
                results.push(0x04); // Indexed name, index 4
                results.push(v.len() as u8); // Length of value
                results.extend_from_slice(v.as_bytes()); // Value bytes
            } else {
                // Custom header with literal name and value (without indexing)
                results.push(0x00); // Literal name, not indexed
                results.push(k.len() as u8); // Length of name
                results.extend_from_slice(k.as_bytes()); // Name bytes
                results.push(v.len() as u8); // Length of value
                results.extend_from_slice(v.as_bytes()); // Value bytes
            }
        });
        results
    }
}

#[derive(Debug)]
struct Frame {
    length: u32,
    frame_type: u8,
    flags: u8,
    stream_id: u32,
    payload: Vec<u8>,
}

// Frame type constants
const FRAME_TYPE_DATA: u8 = 0x0;
const FRAME_TYPE_HEADERS: u8 = 0x1;
const FRAME_TYPE_PRIORITY: u8 = 0x2;
const FRAME_TYPE_RST_STREAM: u8 = 0x3;
const FRAME_TYPE_SETTINGS: u8 = 0x4;
const FRAME_TYPE_PUSH_PROMISE: u8 = 0x5;
const FRAME_TYPE_PING: u8 = 0x6;
const FRAME_TYPE_GOAWAY: u8 = 0x7;
const FRAME_TYPE_WINDOW_UPDATE: u8 = 0x8;
const FRAME_TYPE_CONTINUATION: u8 = 0x9;

// Frame flag constants
const FLAG_END_STREAM: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_PADDED: u8 = 0x8;
const FLAG_PRIORITY: u8 = 0x20;
const FLAG_ACK: u8 = 0x1; // For SETTINGS

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
    
    /// Create a clone of this frame
    fn clone(&self) -> Self {
        Self {
            length: self.length,
            frame_type: self.frame_type,
            flags: self.flags,
            stream_id: self.stream_id,
            payload: self.payload.clone(),
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

            if self.frame_type == 0x0 || self.frame_type == 0x7 {
                println!("ASCII decoded: {}", String::from_utf8_lossy(&self.payload));
                println!();
            } else {
                for b in &self.payload {
                    print!(" {:02x}", b);
                }
                println!();
            }
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
/// Simple decoder for HPACK headers
#[derive(Debug)]
struct HPackDecoder {}

impl HPackDecoder {
    /// Decode HPACK headers from a headers frame payload
    fn decode(payload: &[u8]) -> Vec<(String, String)> {
        let mut headers = Vec::new();
        let mut i = 0;

        while i < payload.len() {
            let b = payload[i];
            i += 1;
            
            // Check if this is an indexed header field
            if b & 0x80 != 0 {
                // Indexed header field
                let index = b & 0x7F;
                match index {
                    8 => headers.push((":status".to_string(), "200".to_string())),
                    9 => headers.push((":status".to_string(), "204".to_string())),
                    10 => headers.push((":status".to_string(), "206".to_string())),
                    11 => headers.push((":status".to_string(), "304".to_string())),
                    12 => headers.push((":status".to_string(), "400".to_string())),
                    13 => headers.push((":status".to_string(), "404".to_string())),
                    14 => headers.push((":status".to_string(), "500".to_string())),
                    // Add other common status codes from the static table
                    _ => headers.push(("unknown-indexed".to_string(), format!("{}", index))),
                }
            } else if b & 0x40 != 0 {
                // Literal header field with incremental indexing
                let index = b & 0x3F;
                if index == 0 {
                    // Read name as string literal
                    if i >= payload.len() {
                        break;
                    }
                    let name_len = payload[i] as usize;
                    i += 1;
                    if i + name_len > payload.len() {
                        break;
                    }
                    let name = String::from_utf8_lossy(&payload[i..i+name_len]).to_string();
                    i += name_len;
                    
                    // Read value
                    if i >= payload.len() {
                        break;
                    }
                    let value_len = payload[i] as usize;
                    i += 1;
                    if i + value_len > payload.len() {
                        break;
                    }
                    let value = String::from_utf8_lossy(&payload[i..i+value_len]).to_string();
                    i += value_len;
                    
                    headers.push((name, value));
                } else {
                    // Handle indexed name (not implemented fully)
                    // Skip value for simplicity
                    if i >= payload.len() {
                        break;
                    }
                    let value_len = payload[i] as usize;
                    i += 1 + value_len;
                }
            } else {
                // Other literals - simplified implementation
                // Skip this header for simplicity
                if i >= payload.len() {
                    break;
                }
                let len = payload[i] as usize;
                i += 1 + len;
                
                if i >= payload.len() {
                    break;
                }
                let value_len = payload[i] as usize;
                i += 1 + value_len;
            }
        }
        
        headers
    }
}

impl Http2Client {
    pub fn new() -> Self {
        Self {}
    }
    
    /// Parse a full HTTP/2 response from frames
    fn parse_response(&self, frames: &[Frame]) -> Result<Response, Error> {
        let mut status = 200;
        let mut headers = Vec::new();
        let mut body = Vec::new();
        
        for frame in frames {
            match frame.frame_type {
                FRAME_TYPE_HEADERS => {
                    // Parse headers using HPACK
                    let decoded = HPackDecoder::decode(&frame.payload);
                    for (name, value) in decoded {
                        if name == ":status" {
                            if let Ok(parsed_status) = value.parse::<u16>() {
                                status = parsed_status;
                            }
                        } else if !name.starts_with(':') {
                            // Only add regular headers, not pseudo-headers
                            headers.push((name, value));
                        }
                    }
                },
                FRAME_TYPE_DATA => {
                    // Append data frame payload to response body
                    body.extend_from_slice(&frame.payload);
                },
                _ => {
                    // Ignore other frame types
                }
            }
        }
        
        Ok(Response::new(status, headers, body))
    }
}

impl HttpClient for Http2Client {
    fn request(&self, req: Request) -> Result<Response, Error> {
        // --- TLS Setup ---
        // Build a rustls ClientConfig with default safe settings.
        let root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec()]; // HTTP/2 protocol identifier

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

        let mut header_map = HashMap::new();
        
        // Extract hostname and path from URL
        let host = req.host();
        let path = if let Some(path_idx) = req.url.find('/', 8) { // Find first '/' after "https://"
            req.url[path_idx..].to_string()
        } else {
            "/".to_string()
        };

        header_map.insert(":method".to_string(), req.method.clone());
        header_map.insert(":scheme".to_string(), "https".to_string());
        header_map.insert(":path".to_string(), path);
        header_map.insert(":authority".to_string(), host);
        
        // Add custom headers
        for (name, value) in &req.headers {
            header_map.insert(name.clone(), value.clone());
        }

        let header_block = HPackEncoder::encode(&header_map);

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
        // Collect all frames until we see END_STREAM on either a HEADERS or DATA frame.
        println!("Reading response frames...");
        let mut response_frames = Vec::new();
        let mut end_stream_seen = false;
        
        // Timeout mechanism (simple implementation)
        let mut frame_count = 0;
        const MAX_FRAMES = 100; // Safety limit to prevent infinite loop
        
        while !end_stream_seen && frame_count < MAX_FRAMES {
            frame_count += 1;
            let frame = match read_frame(&mut stream) {
                Ok(frame) => frame,
                Err(e) => {
                    if frame_count > 5 && !response_frames.is_empty() {
                        // If we've already received some frames, treat errors as end of stream
                        println!("Read error: {}, but continuing with partial response", e);
                        break;
                    } else {
                        return Err(Error::Other(format!("Failed to read frame: {}", e)));
                    }
                }
            };
            
            frame.debug_print("  ");
            response_frames.push(frame.clone());
            
            // Check for END_STREAM flag on HEADERS or DATA frames
            if (frame.frame_type == FRAME_TYPE_HEADERS || frame.frame_type == FRAME_TYPE_DATA) && 
               (frame.flags & FLAG_END_STREAM != 0) {
                println!("Received frame with END_STREAM flag. Finished reading response.");
                end_stream_seen = true;
            }
        }
        
        if frame_count >= MAX_FRAMES && !end_stream_seen {
            println!("Warning: Max frame count reached without END_STREAM");
            // Still try to process what we have
        }
        
        if response_frames.is_empty() {
            return Err(Error::InvalidResponse);
        }
        
        // Parse the response frames into a Response object
        let response = self.parse_response(&response_frames)?;
        println!("Response status: {}", response.status);
        println!("Response body length: {} bytes", response.body.len());
        
        Ok(response)
    }
}
