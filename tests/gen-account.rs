use acme_client::{Account, LetsEncrypt, NewAccount};

#[ignore]
#[tokio::test]
async fn gen_account() {
    // Create a new account. This will generate a fresh ECDSA key for you.
    // Alternatively, restore an account from serialized credentials by
    // using `Account::from_credentials()`.

    let (_account, credentials) = Account::create(
        &NewAccount {
            contact: &[],
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        LetsEncrypt::Staging.url(),
        None,
    )
    .await
    .unwrap();
    println!(
        "account credentials:\nID: {},",
        serde_json::to_string_pretty(&credentials).unwrap()
    );
}
