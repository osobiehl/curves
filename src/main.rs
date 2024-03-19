use coap::client::CoAPClient;
use coap::dtls::{DtlsConfig, DtlsConnection, DtlsResponse};
use coap::UdpCoAPClient;

use coap_lite::{CoapOption, CoapRequest, RequestType as Method};
use pkcs8::{LineEnding, SecretDocument};
use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_ED25519};
use ring::signature::Ed25519KeyPair;
use std::fs::File;
use std::io::{BufReader, Read};
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use webrtc_dtls::cipher_suite::{CipherSuite, CipherSuiteId};
use webrtc_dtls::config::{ClientAuthType, Config, ExtendedMasterSecretType};
use webrtc_dtls::crypto::{Certificate, CryptoPrivateKey, CryptoPrivateKeyKind, OID_ED25519};
use webrtc_dtls::listener::listen;

const SERVER_CERTIFICATE_PRIVATE_KEY: &'static str = "crts/server/srv-key.pem";
const SERVER_CERTIFICATE: &'static str = "crts/server/srv-cert.pem";
const ROOT_CERTIFICATE: &'static str = "crts/root_ca.pem";
const CLIENT_CERTIFICATE_PRIVATE_KEY: &'static str = "crts/client/client-key.pem";
const CLIENT_CERTIFICATE: &'static str = "crts/client/client-crt.pem";
pub fn get_certificate(name: &str) -> rustls::Certificate {
    let mut f = File::open(name).unwrap();
    let mut reader = BufReader::new(&mut f);
    let mut cert_iter = rustls_pemfile::certs(&mut reader);
    let cert = cert_iter
        .next()
        .unwrap()
        .expect("could not get certificate");
    assert!(
        cert_iter.next().is_none(),
        "there should only be 1 certificate in this file"
    );
    return rustls::Certificate(cert.to_vec());
}
pub fn get_private_key(name: &str) -> CryptoPrivateKey {
    let f = File::open(name).unwrap();
    let mut reader = BufReader::new(f);
    let mut buf = vec![];
    reader.read_to_end(&mut buf).unwrap();
    let s = String::from_utf8(buf).expect("utf8 of file");
    // convert key to pkcs8
    //let s = convert_to_pkcs8(&s);

    let mut key_pair = KeyPair::from_pem(s.as_str()).expect("could not parse key");

    //let ed_pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(s.as_str()).expect("key pair in file");
    CryptoPrivateKey::from_key_pair(&key_pair).expect("could not create key pair")
}

pub fn client_key() -> CryptoPrivateKey {
    return get_private_key(CLIENT_CERTIFICATE_PRIVATE_KEY);
}

pub fn server_certificate() -> rustls::Certificate {
    return get_certificate(SERVER_CERTIFICATE);
}
pub fn root_certificate() -> rustls::Certificate {
    return get_certificate(ROOT_CERTIFICATE);
}
pub fn client_certificate() -> rustls::Certificate {
    return get_certificate(CLIENT_CERTIFICATE);
}

pub async fn foo() {
    let server_port = 3333;
    let client_cfg = {
        let mut client_cert_pool = rustls::RootCertStore::empty();
        client_cert_pool
            .add(&root_certificate())
            .expect("ROOT CERTIFICATE!");
        let client_cert = client_certificate();
        let server_cert = server_certificate();
        client_cert_pool
            .add(&server_cert)
            .expect("could not add certificate");

        let client_private_key = client_key();
        let certificate = Certificate {
            certificate: vec![client_cert],
            private_key: client_private_key,
        };

        Config {
            certificates: vec![certificate],
            roots_cas: client_cert_pool,
            mtu: 512,
            flight_interval: Duration::from_secs(60),
            server_name: "txng-draeger".to_string(),

            cipher_suites: vec![
                CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm,
                CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Ccm_8,
                CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256,
                CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_128_Gcm_Sha256,
                CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_256_Cbc_Sha,
                CipherSuiteId::Tls_Ecdhe_Rsa_With_Aes_256_Cbc_Sha,
                CipherSuiteId::Tls_Psk_With_Aes_128_Ccm,
                CipherSuiteId::Tls_Psk_With_Aes_128_Ccm_8,
                CipherSuiteId::Tls_Psk_With_Aes_128_Gcm_Sha256,
            ],
            ..Default::default()
        }
    };
    let dtls_config = DtlsConfig {
        config: client_cfg,
        dest_addr: ("127.0.0.1", server_port)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap(),
    };

    let socket = UdpSocket::bind("127.0.0.1:3337")
        .await
        .expect("could not create socket");
    let dtls_conn = DtlsConnection::from_socket(socket, dtls_config)
        .await
        .expect("could not do handshake");

    let mut client = CoAPClient::from_dtls_connection(dtls_conn);
    client.set_receive_timeout(Duration::from_secs(5));
    client.set_transport_retries(2);
    let domain = format!("127.0.0.1:{}", server_port);
        let start_time = Instant::now();
        let resp = client
            .request_path("/info", Method::Get, None, None, Some(domain.to_string()))
            .await
            .unwrap();
        let end_time = Instant::now();
        let duration = end_time - start_time;

        println!("response len: {:?}", resp.message.payload.len());
        println!("duration: {} ms", duration.as_millis());
        println!(
            "throughput: {}B/s",
            1000.0 * resp.message.payload.len() as f32 / duration.as_millis() as f32
        );
}

async fn client_get() {
    let start_time = Instant::now();
    let mut result = Vec::new();
    for c in b'a'..=b'z' {
        result.extend(std::iter::repeat(c).take(1024));
    }
    let resp = UdpCoAPClient::post("coap://127.0.0.1:5683/block", result)
        .await
        .unwrap();
    let end_time = Instant::now();
    let duration = end_time - start_time;

    println!("response len: {:?}", resp.message.payload.len());
    println!("duration: {} ms", duration.as_millis());
    println!(
        "throughput: {}B/s",
        1000.0 * resp.message.payload.len() as f32 / duration.as_millis() as f32
    );
}

#[tokio::main]
async fn main() {
    foo().await;
    //client_get().await;
}
