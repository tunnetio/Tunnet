//! Touch `last_seen` on activity. Soft-expired devices are not updated.
//! Soft-expire is cleared only via admin/agent TTL patch or re-enroll, not activity.

pub const SLIDE_ON_REGISTER: &str = concat!(
    "UPDATE devices SET last_seen = now() ",
    "WHERE endpoint_id = $1 AND expired_at IS NULL"
);

pub const SLIDE_ON_METADATA: &str = concat!(
    "UPDATE devices SET last_seen = now() ",
    "WHERE endpoint_id = $1 AND expired_at IS NULL"
);

pub const SLIDE_ON_CONNECT: &str = concat!(
    "UPDATE devices SET last_seen = now() ",
    "WHERE endpoint_id = $1 AND expired_at IS NULL"
);

pub const SLIDE_ON_HEARTBEAT: &str = concat!(
    "UPDATE devices SET last_seen = now() ",
    "WHERE endpoint_id = $1 AND expired_at IS NULL"
);
