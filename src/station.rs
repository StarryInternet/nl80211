use crate::attr::{Nl80211Attr, Nl80211RateInfo, Nl80211StaInfo};
use crate::nl80211traits::*;
use crate::parse_attr::{parse_i8, parse_macaddr, parse_u32};
use macaddr::MacAddr;
use neli::err::NlError;
use neli::nlattr::AttrHandle;
use std::fmt;

/// A struct representing a remote station (Access Point)
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Station {
    /// Signal strength average
    pub average_signal: Option<i8>,
    /// Count of times beacon loss was detected
    pub beacon_loss: Option<u32>,
    /// Station bssid
    pub bssid: Option<MacAddr>,
    /// Time since the station is last connected in seconds
    pub connected_time: Option<u32>,
    /// Reception bitrate (u32)
    pub rx_bitrate: Option<u32>,
    /// Total received packets (MSDUs and MMPDUs) from this station
    pub rx_packets: Option<u32>,
    /// Signal strength of last received PPDU
    pub signal: Option<i8>,
    /// Transmission bitrate
    pub tx_bitrate: Option<u32>,
    /// Total failed packets (MPDUs) to this station
    pub tx_failed: Option<u32>,
    /// Total transmitted packets (MSDUs and MMPDUs) to this station
    pub tx_packets: Option<u32>,
    /// Total retries (MPDUs) to this station
    pub tx_retries: Option<u32>,
}

impl FromNlAttributeHandle for Station {
    /// Parse netlink messages returned by the nl80211 command CmdGetStation
    fn from_handle(handle: AttrHandle<Nl80211Attr>) -> Result<Station, NlError> {
        let mut station = Station {
            ..Default::default()
        };
        for attr in handle.iter() {
            match attr.nla_type {
                Nl80211Attr::AttrMac => station.bssid = Some(parse_macaddr(&attr.payload)?),
                Nl80211Attr::AttrStaInfo => {
                    let sub_handle = attr.get_nested_attributes::<Nl80211StaInfo>()?;
                    for sub_attr in sub_handle.iter() {
                        match sub_attr.nla_type {
                            Nl80211StaInfo::StaInfoSignal => {
                                station.signal = Some(parse_i8(&sub_attr.payload))
                            }
                            Nl80211StaInfo::StaInfoSignalAvg => {
                                station.average_signal = Some(parse_i8(&sub_attr.payload))
                            }
                            Nl80211StaInfo::StaInfoBeaconLoss => {
                                station.beacon_loss = Some(parse_u32(&sub_attr.payload))
                            }
                            Nl80211StaInfo::StaInfoConnectedTime => {
                                station.connected_time = Some(parse_u32(&sub_attr.payload))
                            }
                            Nl80211StaInfo::StaInfoRxPackets => {
                                station.rx_packets = Some(parse_u32(&sub_attr.payload))
                            }
                            Nl80211StaInfo::StaInfoTxPackets => {
                                station.tx_packets = Some(parse_u32(&sub_attr.payload))
                            }
                            Nl80211StaInfo::StaInfoTxRetries => {
                                station.tx_retries = Some(parse_u32(&sub_attr.payload))
                            }
                            Nl80211StaInfo::StaInfoTxFailed => {
                                station.tx_failed = Some(parse_u32(&sub_attr.payload))
                            }
                            Nl80211StaInfo::StaInfoRxBitrate => {
                                let bit_rate_handle =
                                    sub_attr.get_nested_attributes::<Nl80211RateInfo>().unwrap();
                                for sub_sub_attr in bit_rate_handle.iter() {
                                    if sub_sub_attr.nla_type == Nl80211RateInfo::RateInfoBitrate32 {
                                        station.rx_bitrate = Some(parse_u32(&sub_sub_attr.payload))
                                    }
                                }
                            }
                            Nl80211StaInfo::StaInfoTxBitrate => {
                                let bit_rate_handle =
                                    sub_attr.get_nested_attributes::<Nl80211RateInfo>().unwrap();
                                for sub_sub_attr in bit_rate_handle.iter() {
                                    if sub_sub_attr.nla_type == Nl80211RateInfo::RateInfoBitrate32 {
                                        station.tx_bitrate = Some(parse_u32(&sub_sub_attr.payload))
                                    }
                                }
                            }
                            _ => (),
                        }
                    }
                }
                _ => (),
            }
        }
        Ok(station)
    }
}

impl fmt::Display for Station {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut result = Vec::new();

        if let Some(bssid) = &self.bssid {
            result.push(format!("bssid : {}", bssid))
        };

        if let Some(connected_time) = self.connected_time {
            result.push(format!(
                "connected time : {} minutes",
                connected_time as f32 / 60.0
            ))
        };

        if let Some(beacon_loss) = &self.beacon_loss {
            result.push(format!("beacon loss : {}", beacon_loss))
        };

        if let Some(signal) = &self.signal {
            result.push(format!("signal : {} dBm", signal))
        };

        if let Some(average_signal) = &self.average_signal {
            result.push(format!("average signal : {} dBm", average_signal))
        };

        if let Some(rx_packets) = &self.rx_packets {
            result.push(format!("rx packets : {}", rx_packets))
        };

        if let Some(tx_packets) = &self.tx_packets {
            result.push(format!("tx packets : {}", tx_packets))
        };

        if let Some(bitrate) = &self.rx_bitrate {
            result.push(format!(
                "rx bitrate : {}.{} Mb/s",
                bitrate / 10,
                bitrate % 10
            ))
        };

        if let Some(bitrate) = &self.tx_bitrate {
            result.push(format!(
                "tx bitrate : {}.{} Mb/s",
                bitrate / 10,
                bitrate % 10
            ))
        }

        if let Some(tx_retries) = &self.tx_retries {
            result.push(format!("tx retries : {}", tx_retries))
        }

        if let Some(tx_failed) = &self.tx_failed {
            result.push(format!("tx failed : {}", tx_failed))
        }

        write!(f, "{}", result.join("\n"))
    }
}

#[cfg(test)]
mod tests_station {
    use super::*;
    use crate::attr::Nl80211Attr::AttrMac;
    use crate::attr::Nl80211Attr::AttrStaInfo;
    use neli::nlattr::Nlattr;

    #[test]
    fn test_pretty_format() {
        let station = Station {
            average_signal: Some(-59),
            beacon_loss: Some(0),
            bssid: Some(MacAddr::from([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])),
            connected_time: Some(5494),
            rx_bitrate: Some(6500),
            rx_packets: Some(425580),
            signal: Some(-61),
            tx_bitrate: Some(8667),
            tx_failed: Some(45),
            tx_packets: Some(153870),
            tx_retries: Some(28425),
        };

        let expected_output = r#"bssid : FF:FF:FF:FF:FF:FF
        connected time : 91.566666 minutes
        beacon loss : 0
        signal : -61 dBm
        average signal : -59 dBm
        rx packets : 425580
        tx packets : 153870
        rx bitrate : 650.0 Mb/s
        tx bitrate : 866.7 Mb/s
        tx retries : 28425
        tx failed : 45"#;

        assert_eq!(
            format!("{}", station),
            expected_output.replace("\n        ", "\n")
        )
    }

    #[test]
    fn test_parser() {
        let handler = vec![
            Nlattr {
                nla_len: 10,
                nla_type: AttrMac,
                payload: vec![46, 46, 46, 46, 46, 46],
            },
            Nlattr {
                nla_len: 2404,
                nla_type: AttrStaInfo,
                payload: vec![
                    8, 0, 16, 0, 17, 27, 0, 0, 8, 0, 1, 0, 248, 2, 0, 0, 8, 0, 2, 0, 43, 98, 156,
                    29, 8, 0, 3, 0, 99, 123, 109, 1, 12, 0, 23, 0, 43, 98, 156, 29, 0, 0, 0, 0, 12,
                    0, 24, 0, 99, 123, 109, 1, 0, 0, 0, 0, 5, 0, 7, 0, 218, 0, 0, 0, 5, 0, 13, 0,
                    215, 0, 0, 0, 20, 0, 25, 0, 5, 0, 0, 0, 216, 0, 0, 0, 5, 0, 1, 0, 213, 0, 0, 0,
                    20, 0, 26, 0, 5, 0, 0, 0, 212, 0, 0, 0, 5, 0, 1, 0, 211, 0, 0, 0, 28, 0, 8, 0,
                    8, 0, 5, 0, 16, 4, 0, 0, 6, 0, 1, 0, 16, 4, 0, 0, 5, 0, 2, 0, 13, 0, 0, 0, 28,
                    0, 14, 0, 8, 0, 5, 0, 134, 1, 0, 0, 6, 0, 1, 0, 134, 1, 0, 0, 5, 0, 2, 0, 4, 0,
                    0, 0, 8, 0, 9, 0, 226, 128, 7, 0, 8, 0, 10, 0, 9, 170, 2, 0, 8, 0, 11, 0, 27,
                    130, 0, 0, 8, 0, 12, 0, 47, 0, 0, 0, 8, 0, 27, 0, 196, 160, 0, 0, 8, 0, 18, 0,
                    0, 0, 0, 0, 28, 0, 15, 0, 4, 0, 2, 0, 4, 0, 3, 0, 5, 0, 4, 0, 1, 0, 0, 0, 6, 0,
                    5, 0, 100, 0, 0, 0, 12, 0, 17, 0, 254, 0, 0, 0, 170, 0, 0, 0, 12, 0, 28, 0,
                    183, 3, 0, 0, 0, 0, 0, 0, 12, 0, 29, 0, 225, 254, 0, 0, 0, 0, 0, 0, 5, 0, 30,
                    0, 216, 0, 0, 0, 5, 0, 34, 0, 46, 0, 0, 0, 56, 8, 31, 0, 128, 0, 1, 0, 12, 0,
                    1, 0, 168, 103, 5, 0, 0, 0, 0, 0, 12, 0, 2, 0, 71, 169, 2, 0, 0, 0, 0, 0, 12,
                    0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 76, 0, 6,
                    0, 8, 0, 1, 0, 0, 0, 0, 0, 8, 0, 2, 0, 0, 0, 0, 0, 8, 0, 3, 0, 61, 39, 1, 0, 8,
                    0, 4, 0, 23, 0, 0, 0, 8, 0, 5, 0, 0, 0, 0, 0, 8, 0, 6, 0, 0, 0, 0, 0, 8, 0, 8,
                    0, 0, 0, 0, 0, 8, 0, 9, 0, 38, 56, 109, 1, 8, 0, 10, 0, 71, 169, 2, 0, 128, 0,
                    2, 0, 12, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    12, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 76,
                    0, 6, 0, 8, 0, 1, 0, 0, 0, 0, 0, 8, 0, 2, 0, 0, 0, 0, 0, 8, 0, 3, 0, 0, 0, 0,
                    0, 8, 0, 4, 0, 0, 0, 0, 0, 8, 0, 5, 0, 0, 0, 0, 0, 8, 0, 6, 0, 0, 0, 0, 0, 8,
                    0, 8, 0, 0, 0, 0, 0, 8, 0, 9, 0, 0, 0, 0, 0, 8, 0, 10, 0, 0, 0, 0, 0, 128, 0,
                    3, 0, 12, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    12, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 76,
                    0, 6, 0, 8, 0, 1, 0, 0, 0, 0, 0, 8, 0, 2, 0, 0, 0, 0, 0, 8, 0, 3, 0, 0, 0, 0,
                    0, 8, 0, 4, 0, 0, 0, 0, 0, 8, 0, 5, 0, 0, 0, 0, 0, 8, 0, 6, 0, 0, 0, 0, 0, 8,
                    0, 8, 0, 0, 0, 0, 0, 8, 0, 9, 0, 0, 0, 0, 0, 8, 0, 10, 0, 0, 0, 0, 0, 128, 0,
                    4, 0, 12, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    12, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 76,
                    0, 6, 0, 8, 0, 1, 0, 0, 0, 0, 0, 8, 0, 2, 0, 0, 0, 0, 0, 8, 0, 3, 0, 0, 0, 0,
                    0, 8, 0, 4, 0, 0, 0, 0, 0, 8, 0, 5, 0, 0, 0, 0, 0, 8, 0, 6, 0, 0, 0, 0, 0, 8,
                    0, 8, 0, 0, 0, 0, 0, 8, 0, 9, 0, 0, 0, 0, 0, 8, 0, 10, 0, 0, 0, 0, 0, 128, 0,
                    5, 0, 12, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    12, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 76,
                    0, 6, 0, 8, 0, 1, 0, 0, 0, 0, 0, 8, 0, 2, 0, 0, 0, 0, 0, 8, 0, 3, 0, 0, 0, 0,
                    0, 8, 0, 4, 0, 0, 0, 0, 0, 8, 0, 5, 0, 0, 0, 0, 0, 8, 0, 6, 0, 0, 0, 0, 0, 8,
                    0, 8, 0, 0, 0, 0, 0, 8, 0, 9, 0, 0, 0, 0, 0, 8, 0, 10, 0, 0, 0, 0, 0, 128, 0,
                    6, 0, 12, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    12, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 76,
                    0, 6, 0, 8, 0, 1, 0, 0, 0, 0, 0, 8, 0, 2, 0, 0, 0, 0, 0, 8, 0, 3, 0, 0, 0, 0,
                    0, 8, 0, 4, 0, 0, 0, 0, 0, 8, 0, 5, 0, 0, 0, 0, 0, 8, 0, 6, 0, 0, 0, 0, 0, 8,
                    0, 8, 0, 0, 0, 0, 0, 8, 0, 9, 0, 0, 0, 0, 0, 8, 0, 10, 0, 0, 0, 0, 0, 128, 0,
                    7, 0, 12, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 2, 0, 180, 0, 0, 0, 0, 0, 0,
                    0, 12, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    76, 0, 6, 0, 8, 0, 1, 0, 0, 0, 0, 0, 8, 0, 2, 0, 0, 0, 0, 0, 8, 0, 3, 0, 180,
                    0, 0, 0, 8, 0, 4, 0, 0, 0, 0, 0, 8, 0, 5, 0, 0, 0, 0, 0, 8, 0, 6, 0, 0, 0, 0,
                    0, 8, 0, 8, 0, 0, 0, 0, 0, 8, 0, 9, 0, 115, 64, 0, 0, 8, 0, 10, 0, 180, 0, 0,
                    0, 128, 0, 8, 0, 12, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 2, 0, 2, 0, 0, 0,
                    0, 0, 0, 0, 12, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 4, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 76, 0, 6, 0, 8, 0, 1, 0, 0, 0, 0, 0, 8, 0, 2, 0, 0, 0, 0, 0, 8, 0, 3, 0,
                    2, 0, 0, 0, 8, 0, 4, 0, 0, 0, 0, 0, 8, 0, 5, 0, 0, 0, 0, 0, 8, 0, 6, 0, 0, 0,
                    0, 0, 8, 0, 8, 0, 0, 0, 0, 0, 8, 0, 9, 0, 32, 1, 0, 0, 8, 0, 10, 0, 2, 0, 0, 0,
                    128, 0, 9, 0, 12, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 2, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 12, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 76, 0, 6, 0, 8, 0, 1, 0, 0, 0, 0, 0, 8, 0, 2, 0, 0, 0, 0, 0, 8, 0, 3, 0, 0,
                    0, 0, 0, 8, 0, 4, 0, 0, 0, 0, 0, 8, 0, 5, 0, 0, 0, 0, 0, 8, 0, 6, 0, 0, 0, 0,
                    0, 8, 0, 8, 0, 0, 0, 0, 0, 8, 0, 9, 0, 0, 0, 0, 0, 8, 0, 10, 0, 0, 0, 0, 0,
                    128, 0, 10, 0, 12, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 2, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 12, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 76, 0, 6, 0, 8, 0, 1, 0, 0, 0, 0, 0, 8, 0, 2, 0, 0, 0, 0, 0, 8, 0, 3, 0, 0,
                    0, 0, 0, 8, 0, 4, 0, 0, 0, 0, 0, 8, 0, 5, 0, 0, 0, 0, 0, 8, 0, 6, 0, 0, 0, 0,
                    0, 8, 0, 8, 0, 0, 0, 0, 0, 8, 0, 9, 0, 0, 0, 0, 0, 8, 0, 10, 0, 0, 0, 0, 0,
                    128, 0, 11, 0, 12, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 2, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 12, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 76, 0, 6, 0, 8, 0, 1, 0, 0, 0, 0, 0, 8, 0, 2, 0, 0, 0, 0, 0, 8, 0, 3, 0, 0,
                    0, 0, 0, 8, 0, 4, 0, 0, 0, 0, 0, 8, 0, 5, 0, 0, 0, 0, 0, 8, 0, 6, 0, 0, 0, 0,
                    0, 8, 0, 8, 0, 0, 0, 0, 0, 8, 0, 9, 0, 0, 0, 0, 0, 8, 0, 10, 0, 0, 0, 0, 0,
                    128, 0, 12, 0, 12, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 2, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 12, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 76, 0, 6, 0, 8, 0, 1, 0, 0, 0, 0, 0, 8, 0, 2, 0, 0, 0, 0, 0, 8, 0, 3, 0, 0,
                    0, 0, 0, 8, 0, 4, 0, 0, 0, 0, 0, 8, 0, 5, 0, 0, 0, 0, 0, 8, 0, 6, 0, 0, 0, 0,
                    0, 8, 0, 8, 0, 0, 0, 0, 0, 8, 0, 9, 0, 0, 0, 0, 0, 8, 0, 10, 0, 0, 0, 0, 0,
                    128, 0, 13, 0, 12, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 2, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 12, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 76, 0, 6, 0, 8, 0, 1, 0, 0, 0, 0, 0, 8, 0, 2, 0, 0, 0, 0, 0, 8, 0, 3, 0, 0,
                    0, 0, 0, 8, 0, 4, 0, 0, 0, 0, 0, 8, 0, 5, 0, 0, 0, 0, 0, 8, 0, 6, 0, 0, 0, 0,
                    0, 8, 0, 8, 0, 0, 0, 0, 0, 8, 0, 9, 0, 0, 0, 0, 0, 8, 0, 10, 0, 0, 0, 0, 0,
                    128, 0, 14, 0, 12, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 2, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 12, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 76, 0, 6, 0, 8, 0, 1, 0, 0, 0, 0, 0, 8, 0, 2, 0, 0, 0, 0, 0, 8, 0, 3, 0, 0,
                    0, 0, 0, 8, 0, 4, 0, 0, 0, 0, 0, 8, 0, 5, 0, 0, 0, 0, 0, 8, 0, 6, 0, 0, 0, 0,
                    0, 8, 0, 8, 0, 0, 0, 0, 0, 8, 0, 9, 0, 0, 0, 0, 0, 8, 0, 10, 0, 0, 0, 0, 0,
                    128, 0, 15, 0, 12, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 2, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 12, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 76, 0, 6, 0, 8, 0, 1, 0, 0, 0, 0, 0, 8, 0, 2, 0, 0, 0, 0, 0, 8, 0, 3, 0, 0,
                    0, 0, 0, 8, 0, 4, 0, 0, 0, 0, 0, 8, 0, 5, 0, 0, 0, 0, 0, 8, 0, 6, 0, 0, 0, 0,
                    0, 8, 0, 8, 0, 0, 0, 0, 0, 8, 0, 9, 0, 0, 0, 0, 0, 8, 0, 10, 0, 0, 0, 0, 0,
                    128, 0, 16, 0, 12, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 2, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 12, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 76, 0, 6, 0, 8, 0, 1, 0, 0, 0, 0, 0, 8, 0, 2, 0, 0, 0, 0, 0, 8, 0, 3, 0, 0,
                    0, 0, 0, 8, 0, 4, 0, 0, 0, 0, 0, 8, 0, 5, 0, 0, 0, 0, 0, 8, 0, 6, 0, 0, 0, 0,
                    0, 8, 0, 8, 0, 0, 0, 0, 0, 8, 0, 9, 0, 0, 0, 0, 0, 8, 0, 10, 0, 0, 0, 0, 0, 52,
                    0, 17, 0, 12, 0, 1, 0, 109, 25, 0, 0, 0, 0, 0, 0, 12, 0, 2, 0, 4, 0, 0, 0, 0,
                    0, 0, 0, 12, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0,
                    0,
                ],
            },
        ];

        let station = Station::from_handle(neli::nlattr::AttrHandle::Owned(handler)).unwrap();
        let expected_station = Station {
            average_signal: Some(-41),
            beacon_loss: Some(0),
            bssid: Some(MacAddr::from([46, 46, 46, 46, 46, 46])),
            connected_time: Some(6929),
            rx_bitrate: Some(390),
            rx_packets: Some(491746),
            signal: Some(-38),
            tx_bitrate: Some(1040),
            tx_failed: Some(47),
            tx_packets: Some(174601),
            tx_retries: Some(33307),
        };

        assert_eq!(station, expected_station)
    }
}
