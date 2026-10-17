// @generated automatically by Diesel CLI.

diesel::table! {
    event (cursor) {
        cursor -> Int8,
        kind -> Text,
        payload -> Jsonb,
        created_at -> Timestamptz,
    }
}
