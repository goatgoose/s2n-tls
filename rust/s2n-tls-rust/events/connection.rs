#[event("transport:application_protocol_information")]
struct ApplicationProtocolInformation<'a> {
    chosen_application_protocol: &'a [u8],
}
