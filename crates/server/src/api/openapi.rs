//! What the document says beyond the routes: its title and version, how a client
//! authenticates, and the refusals operations share.

use landfall_api::Problem;
use landfall_core::protocol::PROBLEM_CONTENT_TYPE;
use utoipa::openapi::response::{Response, ResponseBuilder};
use utoipa::openapi::schema::{ObjectBuilder, Type};
use utoipa::openapi::security::{ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::openapi::{ContentBuilder, Header, OpenApi, Ref, RefOr};
use utoipa::{Modify, ToResponse};

/// The document's fixed part. `info.version` is the API's version, not the controller's, so
/// that a release leaves the document alone.
#[derive(utoipa::OpenApi)]
#[openapi(
    version = "3.1.0",
    info(
        title = "landfall",
        version = "1",
        description = "The landfall controller's API for people and their agents. Within \
                       `/api/v1`, fields and values are only added: an older client works with \
                       a newer controller.",
        license(name = "MIT OR Apache-2.0", identifier = "MIT OR Apache-2.0"),
    ),
    components(
        schemas(Problem),
        responses(Unauthenticated, Forbidden, NotFound, RateLimited, BadRequest),
    ),
    modifiers(&Schemes),
)]
pub(super) struct ApiDoc;

/// The two ways to authenticate. Each operation's `security` lists, under each, the roles
/// that may call it: the configuration's `view`, `request`, `approve` and `rollback`, and
/// `requester` for who asked. An empty list is any authenticated principal.
struct Schemes;

impl Modify for Schemes {
    fn modify(&self, openapi: &mut OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "token",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .description(Some(
                        "An API token from `landfall-server token`. A token never approves.",
                    ))
                    .build(),
            ),
        );
        components.add_security_scheme(
            "session",
            SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::with_description(
                "__Host-landfall-session",
                "A passkey sign-in on the controller's own pages. A state change also needs \
                 the configured `Origin`.",
            ))),
        );
    }
}

/// A refusal with this description, as `Problem`.
fn problem(description: &str) -> ResponseBuilder {
    ResponseBuilder::new().description(description).content(
        PROBLEM_CONTENT_TYPE,
        ContentBuilder::new()
            .schema(Some(Ref::from_schema_name("Problem")))
            .build(),
    )
}

/// One reusable refusal: its name in the document, and what it says.
macro_rules! refusal {
    ($name:ident, $description:expr) => {
        #[doc = $description]
        pub(crate) struct $name;

        impl<'r> ToResponse<'r> for $name {
            fn response() -> (&'r str, RefOr<Response>) {
                (stringify!($name), problem($description).build().into())
            }
        }
    };
}

refusal!(
    Unauthenticated,
    "No credentials, or ones that aren't good: `unauthenticated`."
);
refusal!(
    Forbidden,
    "The principal may see this and no grant lets it do that, or a session's state change \
     didn't come from the controller's origin: `forbidden`, `bad_origin`."
);
refusal!(
    NotFound,
    "No such thing, as far as this principal may know: one they have no grant on reads the \
     same as one that doesn't exist. `not_found`."
);
refusal!(
    BadRequest,
    "The body isn't the request this operation takes: `bad_request`."
);

/// Too many requests by this principal or from this source.
pub(crate) struct RateLimited;

impl<'r> ToResponse<'r> for RateLimited {
    fn response() -> (&'r str, RefOr<Response>) {
        let wait = Header::new(ObjectBuilder::new().schema_type(Type::Integer));
        let response = problem("Too many requests: wait for `Retry-After`. `rate_limited`.")
            .header("Retry-After", wait)
            .build();
        ("RateLimited", response.into())
    }
}
