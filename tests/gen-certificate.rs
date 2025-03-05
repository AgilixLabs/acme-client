use base64::prelude::{Engine, BASE64_URL_SAFE_NO_PAD};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use serde_json::json;
use std::time::Duration;
use tokio::time::sleep;
use wallee::wallee;

use acme_client::{Account, AuthorizationStatus, ChallengeType, Identifier, NewOrder, OrderStatus};

const ID: &str = "https://acme-staging-v02.api.letsencrypt.org/acme/acct/149151684";
const KEY: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgtdWjsMiZj6PJ7ogxBbzWxKYPr0OdhujXedeLA3mHjUKhRANCAARwGvxlpMMlkzxIFO4qzpa-nBXgBrGcuQ1L-bVXwENeKQZJVS6uPzHQwrYb-Bu8pEGn4vfe7og4kApao04RyNQt";
const DIRECTORY_URL: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
const DNS_NAME: &str = "xxx.agilixdawndev.com";

#[ignore]
#[tokio::test]
async fn gen_certificate() {
    let key = BASE64_URL_SAFE_NO_PAD.decode(KEY).unwrap();
    let account = Account::from_parts(ID, &key, DIRECTORY_URL).await.unwrap();

    // Create the ACME order based on the given domain names.
    // Note that this only needs an `&Account`, so the library will let you
    // process multiple orders in parallel for a single account.

    let identifier = Identifier::Dns(DNS_NAME.into());
    let mut order = account
        .new_order(&NewOrder {
            identifiers: &[identifier],
        })
        .await
        .unwrap();

    let state = order.state();
    println!("order state: {:#?}", state);
    assert!(matches!(
        state.status,
        OrderStatus::Pending | OrderStatus::Ready
    ));

    // Pick the desired challenge type and prepare the response.

    let authorizations = order.authorizations().await.unwrap();
    let mut challenges = Vec::with_capacity(authorizations.len());
    for authz in &authorizations {
        match authz.status {
            AuthorizationStatus::Pending => {}
            AuthorizationStatus::Valid => continue,
            _ => todo!(),
        }

        // We'll use the DNS challenges for this example, but you could
        // pick something else to use here.

        let challenge = authz
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Dns01)
            .ok_or_else(|| wallee!("no dns01 challenge found"))
            .unwrap();

        let Identifier::Dns(identifier) = &authz.identifier;

        let msg = format!(
            "_acme-challenge.{} IN TXT {}",
            identifier,
            order.key_authorization(challenge).dns_value()
        );
        println!("Please set the following DNS record then press the Return key:");
        println!("{msg}");

        challenges.push((identifier, &challenge.url));
    }

    // Let the server know we're ready to accept the challenges.

    for (_, url) in &challenges {
        order.set_challenge_ready(url).await.unwrap();
    }

    // Exponentially back off until the order becomes ready or invalid.

    let mut tries = 1u8;
    let mut delay = Duration::from_millis(250);
    loop {
        sleep(delay).await;
        let state = order.refresh().await.unwrap();
        if let OrderStatus::Ready | OrderStatus::Invalid = state.status {
            println!("order state: {:#?}", state);
            break;
        }

        delay *= 2;
        tries += 1;
        match tries < 10 {
            true => {
                println!("order is not ready\nstate: {state:?}\ntries: {tries}\nwaiting {delay:?}")
            }
            false => {
                println!("error: order is not ready\nstate: {state:#?}\ntries: {tries}");
                panic!("order is not ready");
            }
        }
    }

    let state = order.state();
    if state.status != OrderStatus::Ready {
        panic!("unexpected order status: {:?}", state.status);
    }

    // let mut names = Vec::with_capacity(challenges.len());
    // for (identifier, _) in challenges {
    //     names.push(identifier.to_owned());
    // }
    let names = vec![DNS_NAME.to_owned()];

    // If the order is ready, we can provision the certificate.
    // Use the rcgen library to create a Certificate Signing Request.
    let subject_key = KeyPair::generate().unwrap();

    let mut params = CertificateParams::new(names.clone()).unwrap();
    params.distinguished_name = DistinguishedName::new();
    // let cert = Certificate::from_params(params).unwrap();
    // let csr = cert.serialize_request_der()?;
    let csr = params.serialize_request(&subject_key).unwrap();

    // Finalize the order and print certificate chain, private key and account credentials.

    order.finalize(csr.der()).await.unwrap();
    let cert_chain_pem = loop {
        match order.certificate().await.unwrap() {
            Some(cert_chain_pem) => break cert_chain_pem,
            None => sleep(Duration::from_secs(1)).await,
        }
    };

    println!("certficate chain:\n{}", json!(cert_chain_pem));
    println!("private key:\n{}", json!(subject_key.serialize_pem()));

    println!("OK");
}
