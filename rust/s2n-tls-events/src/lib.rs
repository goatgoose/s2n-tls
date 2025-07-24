pub mod event;
pub mod ffi;

#[unsafe(no_mangle)]
pub extern "C" fn rust_function() {
    println!("Hello from Rust!");
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;
    use std::time::Duration;
    use s2n_quic_core::event::IntoEvent;
    use s2n_quic_core::time::Timestamp;
    use crate::event::api::{ApplicationProtocolInformation, ConnectionInfo, ConnectionMeta};
    use crate::event::ConnectionPublisher;
    use super::*;

    #[test]
    fn events() {
        struct TestSubscriber {};

        impl event::Subscriber for TestSubscriber {
            type ConnectionContext = ();

            fn create_connection_context(&self, meta: &ConnectionMeta, info: &ConnectionInfo) -> Self::ConnectionContext {
                ()
            }

            fn on_application_protocol_information(&self, context: &Self::ConnectionContext, meta: &ConnectionMeta, event: &ApplicationProtocolInformation) {
                println!("alpn: {:?}", event.chosen_application_protocol);
            }
        }

        let subscriber = TestSubscriber {};

        let publisher = event::ConnectionPublisherSubscriber::<TestSubscriber>::new(
            event::builder::ConnectionMeta {
                id: 0,
                timestamp: unsafe { s2n_quic_core::time::Timestamp::from_duration(Duration::from_secs(10)) }.into_event(),
            },
            0,
            &subscriber,
            &(),
        );

        publisher.on_application_protocol_information(event::builder::ApplicationProtocolInformation {
            chosen_application_protocol: "h2".as_bytes(),
        });
    }
}
