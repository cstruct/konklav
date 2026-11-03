//! Shares: their terms in both directions, and the shares written.

use konklav_api as api;
use konklav_store::shares::{Share, ShareState, ShareTerms, Side};

pub(crate) fn share(share: Share) -> api::Share {
    let terms = share.terms;
    api::Share {
        id: share.id,
        terms: api::ShareTerms {
            owner: terms.owner,
            scope: terms.scope,
            recipient: terms.recipient,
            recipient_scope: terms.recipient_scope,
            actions: terms.actions,
            attributes: terms.attributes,
            valid_from: terms.valid_from,
            valid_until: terms.valid_until,
        },
        state: match share.state {
            ShareState::Offered => api::ShareState::Offered,
            ShareState::Accepted => api::ShareState::Accepted,
            ShareState::Revoked => api::ShareState::Revoked,
        },
        accepted_at: share.accepted_at,
        revoked_at: share.revoked_at,
        revoked_by: share.revoked_by.map(share_side),
        created_at: share.created_at,
        updated_at: share.updated_at,
    }
}

pub(crate) fn share_terms(terms: api::ShareTerms) -> ShareTerms {
    ShareTerms {
        owner: terms.owner,
        scope: terms.scope,
        recipient: terms.recipient,
        recipient_scope: terms.recipient_scope,
        actions: terms.actions,
        attributes: terms.attributes,
        valid_from: terms.valid_from,
        valid_until: terms.valid_until,
    }
}

fn share_side(side: Side) -> api::ShareSide {
    match side {
        Side::Owner => api::ShareSide::Owner,
        Side::Recipient => api::ShareSide::Recipient,
    }
}

pub(crate) fn store_share_side(side: api::ShareSide) -> Side {
    match side {
        api::ShareSide::Owner => Side::Owner,
        api::ShareSide::Recipient => Side::Recipient,
    }
}

#[cfg(test)]
mod tests {
    use konklav_store::shares::{Share, ShareState, ShareTerms, Side};
    use serde_json::json;

    /// The transport types write and read the storage models' JSON.
    #[test]
    fn shares_keep_the_storage_models_shape() {
        let terms: ShareTerms = serde_json::from_value(json!({
            "owner": "0195e0a0-0000-7000-8000-000000000001",
            "scope": {"kind": "project", "id": "p1"},
            "recipient": "0195e0a0-0000-7000-8000-000000000002",
            "actions": ["document:read"],
            "attributes": {"data_range": {"from": "2026-01-01", "until": "2026-12-31"}},
            "valid_until": "2027-01-01T00:00:00Z",
        }))
        .unwrap();
        let read: konklav_api::ShareTerms =
            serde_json::from_value(serde_json::to_value(&terms).unwrap()).unwrap();
        assert_eq!(super::share_terms(read), terms);
        let share = Share {
            id: uuid::Uuid::now_v7().into(),
            terms,
            state: ShareState::Revoked,
            accepted_at: Some(chrono::Utc::now()),
            revoked_at: Some(chrono::Utc::now()),
            revoked_by: Some(Side::Recipient),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        assert_eq!(
            serde_json::to_value(super::share(share.clone())).unwrap(),
            serde_json::to_value(&share).unwrap()
        );
    }
}
