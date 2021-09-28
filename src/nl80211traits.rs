use crate::attr::Nl80211Attr;
use neli::err::NlError;
use neli::nlattr::AttrHandle;

/// Construct object by parsing netlink messages attributes returned by a nl80211 command
pub trait FromNlAttributeHandle {
    fn from_handle(handle: AttrHandle<Nl80211Attr>) -> Result<Self, NlError>
    where
        Self: Sized;
}

/// Decode netlink payloads (Vec\<u8\>) to appropriate types
pub trait NlPayloadDecode {
    fn decode(&mut self) -> Self;
}
