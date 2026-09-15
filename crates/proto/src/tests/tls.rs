//! Certificate authentication contract for the shared test identity.

use openssl::error::ErrorStack;
pub(crate) use test_support::tls::TestIdentity;

#[test]
fn certificate_requires_correct_root_and_name() -> Result<(), ErrorStack> {
    use openssl::{
        stack::Stack,
        x509::{store::X509StoreBuilder, verify::X509VerifyParam, X509StoreContext},
    };

    let identity = TestIdentity::new("ns.example.test")?;
    let unrelated = TestIdentity::new("ns.example.test")?;
    for (root, name, expected) in [
        (&identity.ca, "ns.example.test", true),
        (&identity.ca, "wrong.example.test", false),
        (&unrelated.ca, "ns.example.test", false),
    ] {
        let mut store = X509StoreBuilder::new()?;
        store.add_cert(root.to_owned())?;
        let mut params = X509VerifyParam::new()?;
        params.set_host(name)?;
        store.set_param(&params)?;
        let chain = Stack::new()?;
        let verified =
            X509StoreContext::new()?.init(&store.build(), &identity.cert, &chain, |ctx| {
                ctx.verify_cert()
            })?;
        assert_eq!(verified, expected);
    }
    Ok(())
}
