# ClickKart Auth Service

Item **#4** in the fixed ClickKart build order (Eureka → Config Server → Gateway → **Auth** →
User → ... → Admin). Registration, login (email/mobile/publicId), JWT access + opaque refresh
token issuance, account lockout, logout/token revocation, and RBAC source of truth for the
platform's 4 roles.

## Tech stack

| Layer | Version |
|---|---|
| Language | Java 21 |
| Framework | Spring Boot 4.0.7 |
| Cloud | Spring Cloud 2025.1.2 |
| Security | Spring Security (stateless JWT, HMAC-SHA256 via jjwt 0.12.6), BCrypt |
| Persistence | Spring Data JPA + PostgreSQL, `ddl-auto=update` (no Flyway/Liquibase - project decision) |
| Cache | Redis (revoked-jti store, shared keyspace with the Gateway) |
| Inter-service | OpenFeign + Resilience4j (Audit Log Service, not yet built) |
| Build | Maven |
| Container | Docker / Docker Compose |

## Project structure

```
clickkart-auth-service/
├── pom.xml
├── Dockerfile
├── Jenkinsfile
├── docker/
│   ├── docker-compose.yml          # base service + bundled Postgres (inner-loop dev only)
│   ├── docker-compose.dev.yml
│   ├── docker-compose.test.yml
│   ├── docker-compose.qa.yml
│   └── docker-compose.prod.yml
└── src/
    ├── main/java/com/clickkart/auth/
    │   ├── AuthServiceApplication.java
    │   ├── config/          # SecurityConfig, AuthProperties, WebConfig, OpenApiConfig,
    │   │                     # RequiredEurekaClientConfig, RoleSeeder, AuditChainSeeder
    │   ├── constant/         # ApiPaths, LoggerNames, MdcKeys (plain string-constant holders)
    │   ├── enums/            # RoleType, AuditAction, AuditOutcome, LoginFailureReason, OtpChannel
    │   ├── jwt/              # JwtService, JwtAuthenticationFilter, JwtClaimNames
    │   ├── filter/           # MdcCleanupFilter, AccessLogFilter, RateLimitFilter (non-JWT
    │   │                     # servlet filters)
    │   ├── web/              # ClientIpResolver (shared between AuthController + RateLimitFilter)
    │   ├── controller/       # AuthController, AuditController (build ApiResponse for every
    │   │                     # success response; Swagger @Tag/@Operation annotated)
    │   ├── dto/              # ApiResponse, ErrorDetail, PageResponse, PasswordPolicy
    │   │   ├── request/      # *Request records (Bean Validation annotated)
    │   │   └── response/     # *Response records
    │   ├── entity/           # ClickKartUserEntity, RoleEntity, UserRoleEntity, RefreshTokenEntity,
    │   │                     # PasswordResetTokenEntity, PasswordHistoryEntity, LoginOtpEntity,
    │   │                     # LoginAuditEntity, AuditLogEntryEntity, AuditChainHeadEntity - every
    │   │                     # one extends BaseEntity (id/createdBy/createdDate/updatedBy/
    │   │                     # updatedDate/version); AssignedOrSequenceIdGenerator is the one
    │   │                     # exception's plumbing (see AuditChainHeadEntity's fixed singleton id)
    │   ├── exception/        # custom exceptions + AuthExceptionHandler (builds ApiResponse errors)
    │   ├── feign/            # AuditLogServiceClient + NotificationServiceClient (+ fallbacks)
    │   ├── repository/       # Spring Data repositories + *Specifications
    │   ├── security/         # AuthenticatedPrincipal, ClickKartUserDetailsService/Principal,
    │   │                     # RevocationService, TokenRevocationLogoutHandler, Rest*Handler
    │   ├── service/          # interfaces only: AuthService, AuditTrailService, AuthFailureRecorder,
    │   │                     # RefreshTokenService, PasswordResetService, PasswordPolicyService, OtpService
    │   └── serviceimpl/      # the above interfaces' sole implementations
    ├── main/resources/
    │   ├── application.properties   # Config Server bootstrap + profile-invariant settings only
    │   └── logback-spring.xml       # APPLICATION/ERROR/AUDIT/SECURITY/SQL/ACCESS appenders
    └── test/java/com/clickkart/auth/
        ├── jwt/JwtServiceTest.java
        └── serviceimpl/{AuthServiceImplTest,AuditTrailServiceTest}.java
```

## Configuration & profiles

All datasource, JWT, lockout, refresh, Redis, Feign/Resilience4j, and logging settings are
pulled per-profile from `clickkart-config-repository/clickkart-auth-service-{dev,test,qa,prod}.properties`
via the Config Server (item #2) - nothing environment-specific is hardcoded here.

| Profile | DB host default | Eureka/Config creds | Notes |
|---|---|---|---|
| `dev` | `localhost` fallback | default `admin`/`dev-only-secret-change-me` | Eclipse-friendly, everything optional |
| `test` | `postgres-auth-test`, no fallback | required, no default | CI fails fast if unset |
| `qa` | `postgres-auth-qa`, no fallback | required, no default | shared QA environment |
| `prod` | required, no default | required, no default | `logging.structured.format.console=ecs` |

Every profile sets `spring.jpa.hibernate.ddl-auto=update` - **there is no Flyway/Liquibase
migration in this service**, per an explicit project decision overriding the originally-locked
architecture table. Hibernate creates/alters the schema at boot in every environment including
prod; there is no schema_version history or rollback step, which is a real, accepted trade-off
against Rule 14's normal "production-grade" bar - flagging it here rather than glossing over it.

**Known sharp edge**: `ddl-auto=update` only ever *adds* missing tables/columns - it never widens
an existing constraint. Hibernate 6+ auto-generates a `CHECK` constraint for any `@Enumerated
(EnumType.STRING)` column, frozen at whatever enum values exist the moment that table is first
created. Adding a new enum constant later (which has already happened repeatedly to `AuditAction`)
gets silently rejected by the stale constraint in any environment where the table already exists,
until it's manually dropped (`ALTER TABLE audit_log_entries DROP CONSTRAINT
audit_log_entries_action_check;`) - the exact same class of gap as the `roles.created_date`
`NOT NULL` issue this checklist already flagged elsewhere. Every enum-typed column in this service
now pairs `@Enumerated(EnumType.STRING)` with `@JdbcTypeCode(SqlTypes.VARCHAR)` specifically to
prevent Hibernate from generating that constraint in the first place - keep doing this for any new
enum-typed column, rather than rediscovering this the hard way again.

## Security model

- **Access tokens**: HMAC-SHA256 JWTs, 15 min default TTL, signed with `JWT_SECRET` (must match
  the Gateway's own `JWT_SECRET` exactly - no shared library, so both sides configure it
  independently). Claims: `sub` (`ClickKartUserEntity.publicId`, e.g. `USR-...` - never the internal
  auto-generated `Long` PK), `jti`, `roles` (comma-joined), `correlationId`.
- **Refresh tokens**: opaque, high-entropy random strings (never JWTs) - only their SHA-256 hash
  is persisted, so a database read alone can never be replayed. Rotated on every `/refresh` call
  (old one revoked, new one issued) and carry the same `correlationId` for the life of the login
  session (Rule 13).
- **This service validates every token itself** via `JwtAuthenticationFilter` - it never trusts
  `X-User-Id`/`X-User-Roles` headers forwarded by the Gateway, since a request reaching this
  service directly (bypassing the Gateway) must be rejected/accepted on the token's own merits.
- **Account lockout**: configurable max failed attempts (`auth.max-failed-login-attempts`,
  default 5) and lockout duration (`auth.lockout-duration-minutes`, default 15). `ClickKartUserEntity`
  tracks this via `accountNonLocked`/`lockTime`/`failedLoginAttempts`, with time-based
  auto-unlock on the next login attempt once the lockout window has elapsed. Shared across both
  login paths - a wrong OTP guess counts toward, and is subject to, the exact same lockout a
  wrong password would trigger.
- **OTP login**: a full alternative to password login, not a second factor - `POST
  /otp/request` (`channel`: `SMS` or `EMAIL`) issues a short numeric code (`auth.otp-length`,
  default 6 digits), single-use and hashed at rest like a refresh/reset token, valid for
  `auth.otp-ttl-seconds` (default 300s). Requesting a new code invalidates any still-outstanding
  one. Unlike the account-level lockout, each individual OTP also burns itself out after
  `auth.otp-max-verify-attempts` (default 5) wrong guesses, independent of whether the account
  itself has crossed its own lockout threshold yet. `POST /otp/verify` mints the same
  `tokens`+`user` shape `/login` does.
- **Logout**: pushes the current access token's `jti` into the same Redis keyspace
  (`revoked:jti:<jti>`) the Gateway checks on every request, and revokes the refresh token
  (or every active refresh token for the account, if none was supplied).
- **Correlation id (Rule 13)**: minted once at login (or OTP verification), reused across every
  refresh in that session, required on every other endpoint (`MissingCorrelationIdException` →
  400 if absent from an already-validated token).
- **Rate limiting**: `RateLimitFilter` throttles `/register`, `/login`, `/refresh`,
  `/forgot-password`, `/reset-password`, `/otp/request`, `/otp/verify` per IP
  (`auth.rate-limit-max-requests` per `auth.rate-limit-window-seconds`, Redis-backed fixed
  window) - see Production Hardening checklist below for the full rationale.
- **Failure-path bookkeeping runs in its own transaction**: `AuthFailureRecorder` persists the
  lockout counter, `LoginAuditEntity`, tamper-evident audit record, refresh-token-family
  revocation, and an OTP's/verification code's attempt counter via `Propagation.REQUIRES_NEW` -
  the caller is about to throw the very exception the failure represents, and without an
  independent transaction Spring's default rollback-on-exception behavior would silently undo all
  of it. Also why `LoginOtpRepository`'s and `VerificationCodeRepository`'s lookups are
  deliberately *not* pessimistic-locked, unlike the refresh/reset token lookups - see those
  repositories' Javadoc.
- **`RefreshTokenServiceImpl.rotate()` uses `noRollbackFor`, not `REQUIRES_NEW`**: its
  ineligible-account branch revokes the refresh token it just looked up before rejecting the
  request - but that row is already pessimistic-write-locked by this same transaction
  (`findByTokenHashForUpdate`), so a `REQUIRES_NEW` write to persist the revoke would deadlock
  against its own outer transaction. `@Transactional(noRollbackFor =
  InvalidRefreshTokenException.class)` lets the transaction commit (preserving the revoke) despite
  still throwing - set identically on both `rotate()` and `AuthServiceImpl.refresh()`, since
  Spring's rollback-only flag is a one-way latch any interceptor in the call chain can set. Also
  why `lockAccount`/`deleteAccount` proactively revoke every active refresh token for the target
  account up front (`TokenRevocationLogoutHandler.revokeAllActiveTokensForAccount`), rather than
  relying solely on this reactive, per-token check.
- **Email/mobile verification**: authenticated self-service, structurally close to OTP login
  (short numeric code, hashed at rest, single-use) but a deliberately separate entity
  (`VerificationCodeEntity`/`VerificationCodeService`) - it proves ownership of a contact detail,
  not a login credential, so a wrong guess here never touches account-level lockout. `channel`
  doubles as which attribute is being verified (`EMAIL`/`SMS`), so an account may have one
  outstanding code per channel at once. Valid for `auth.verification-code-ttl-seconds` (default
  86400s - far longer than login OTP's 300s, since confirming a contact detail isn't
  time-pressured) and burns itself out after `auth.verification-code-max-verify-attempts`
  (default 5) wrong guesses.
- **Account deletion**: ADMIN-only soft delete (`ClickKartUserEntity.softDelete()` -
  `deleted=true`, excluded from every query thereafter via `@SQLRestriction`) that also revokes
  every active refresh token for the account. An already-issued, unexpired access token has no
  known `jti` to revoke for an arbitrary target account and remains valid until natural TTL
  expiry - the same pre-existing limitation `lockAccount` already has.

## API endpoints

Full interactive docs (springdoc-openapi): `http://localhost:8081/swagger-ui.html` once the
service is running. Every endpoint below returns the same `ApiResponse` envelope on both
success and error.

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/api/v1/auth/register` | Public | Always creates a `ROLE_CUSTOMER` account and logs it in immediately (same `tokens`+`user` shape as login) |
| POST | `/api/v1/auth/login` | Public | `identifier` = email, mobile number, or publicId |
| POST | `/api/v1/auth/refresh` | Public | Rotates the refresh token; reuse triggers session-family revocation |
| POST | `/api/v1/auth/logout` | Bearer | Body optional - omit to revoke every refresh token |
| POST | `/api/v1/auth/forgot-password` | Public | Always responds identically, whether or not `identifier` resolves |
| POST | `/api/v1/auth/reset-password` | Public | Consumes the token issued by forgot-password |
| POST | `/api/v1/auth/otp/request` | Public | `channel` = `SMS` or `EMAIL`; always responds identically, whether or not `identifier` resolves |
| POST | `/api/v1/auth/otp/verify` | Public | Alternative to password login, not a second factor - same `tokens`+`user` shape as login |
| POST | `/api/v1/auth/change-password` | Bearer | Requires `currentPassword`; rejects reuse of the last N passwords |
| POST | `/api/v1/auth/verify-contact/request` | Bearer | Self-service; `channel` = `EMAIL` or `SMS` selects which of the caller's own contact details to verify |
| POST | `/api/v1/auth/verify-contact/confirm` | Bearer | Self-service; marks the caller's own email/mobile verified once the code checks out |
| GET | `/api/v1/auth/accounts` | Bearer, ADMIN | Paginated/filterable (`roleType`, `locked`, `email`) |
| POST | `/api/v1/auth/accounts/{publicId}/lock` | Bearer, ADMIN | |
| POST | `/api/v1/auth/accounts/{publicId}/unlock` | Bearer, ADMIN | Also resets the failed-attempt counter |
| POST | `/api/v1/auth/accounts/{publicId}/delete` | Bearer, ADMIN | Soft delete (`deleted=true`); also revokes every active refresh token for the account |
| GET | `/api/v1/auth/audit` | Bearer, ADMIN | Paginated, chain order |
| GET | `/api/v1/auth/audit/verify` | Bearer, ADMIN | Recomputes the hash chain, reports the first break if any |

## Audit trail (banking-grade)

Every write operation (register/login/OTP-login/refresh/logout/admin listing) **and every
security-relevant rejection** is recorded by `AuditTrailService` as an immutable, hash-chained
`AuditLogEntryEntity` row - the local, transactional system of record, not just a log line. Beyond
the account-lifecycle actions, the chain also captures: refresh-token reuse (a stolen token being
replayed), unknown-identifier login attempts (password or OTP), revoked-access-token reuse,
rate-limit-exceeded (once per window, not once per rejected request - see `RateLimitFilter`
Javadoc for why), access-denied (an authenticated user hitting an endpoint their role doesn't
permit), and an ADMIN browsing the trail or running an integrity check (`GET /audit`, `GET
/audit/verify`) - reading the trail is itself an activity worth a durable trace, not just the
ordinary `AccessLogFilter` line. A verify call that finds the chain broken records that finding as
a `FAILURE`-outcome entry in the same trail, so *when* tampering was first detected is itself
permanently on the record. Deliberately **not** chained: ordinary invalid/expired-token
rejections - ubiquitous, benign token expiry would otherwise serialize every authenticated request
through the chain's single-row lock for no security value.

- **Audit-or-abort**: the audit write happens inside the same `@Transactional` service method as
  the business operation it's recording. If the audit insert fails, the whole transaction rolls
  back - a login/register/logout can never silently "succeed" without leaving a trace.
- **Tamper-evident hash chain**: each entry's `entryHash` is the SHA-256 of its own fields plus
  the previous entry's hash (`previousEntryHash`) - altering any historical row, even by one
  character, breaks the chain from that point forward. `AuditChainHeadEntity` (a locked singleton row,
  `@Lock(PESSIMISTIC_WRITE)`) serializes concurrent writers onto one total order so the chain
  can't fork.
- **Append-only by construction**: `AuditLogEntryRepository`/`AuditChainHeadRepository` extend
  the bare Spring Data `Repository` marker, not `JpaRepository` - there is no `deleteById`/
  `deleteAll` exposed at all, at the API level, not just by convention.
- **Verifiable**: `GET /api/v1/auth/audit/verify` (ADMIN) recomputes every entry's hash and
  reports the first break, if any. `GET /api/v1/auth/audit` (ADMIN, paginated) browses the trail,
  each entry including its own hash for independent cross-checking.
- **Best-effort centralized aggregation**: after the local durable write, the same event is also
  forwarded to the (not-yet-built) Audit Log Service via Feign - non-blocking, fallback-protected,
  supplementary only. The local table is authoritative.
- **Structured JSON logs**: the AUDIT/SECURITY/ACCESS log files (`logstash-logback-encoder`) are
  SIEM-ingestible JSON, not plain text - every line carries the correlation id automatically via
  MDC.

## Running locally (Eclipse)

1. **File → Import → Maven → Existing Maven Projects** → select `clickkart-auth-service`.
2. Ensure JDK 21 is selected (Project → Properties → Java Build Path / Java Compiler → 21).
3. Start Eureka, Config Server, and API Gateway first (build order).
4. **Right-click `AuthServiceApplication.java` → Run As → Spring Boot App** (defaults to `dev`).
   Needs a local Postgres reachable at `localhost:5432` with a `clickkart_auth` database (or run
   `docker compose -f docker/docker-compose.yml -f docker/docker-compose.dev.yml up auth-postgres -d`
   for just the database, then run the app from Eclipse).
5. Confirm startup: console shows the banner + `Started AuthServiceApplication`; check the
   Eureka dashboard for a `CLICKKART-AUTH-SERVICE` entry; `http://localhost:8081/actuator/health`
   returns `{"status":"UP"}`, and the k8s-style probe sub-paths both resolve too:
   `http://localhost:8081/actuator/health/readiness` and `.../health/liveness`.
6. Through the Gateway: `POST http://localhost:8080/api/v1/auth/register` with
   `{"email":"jane@example.com","mobileNumber":"9845550100","password":"Str0ng!Passw0rd"}`
   → `201 Created`.

Maven CLI alternative - `-P<env>` selects the Spring profile via the Maven profiles in `pom.xml`
(pure convenience, no build/dependency differences between them - actual config still comes
entirely from the Config Server):

```bash
mvn spring-boot:run -Pqa
```

## Running in Docker

Copy `.env.example` to `.env` first (documents every environment variable this service reads
across all 4 profiles - dev has safe fallbacks for everything, test/qa/prod don't):

```bash
cp .env.example .env
docker compose -f docker/docker-compose.yml -f docker/docker-compose.dev.yml up --build -d
```

Or as part of the full application tier (see repo root):

```bash
docker compose -f docker-compose.dev-infra.yml -f docker-compose.app-tier.yml up -d
```

## Observability & Metrics

- **Health**: `/actuator/health` (aggregate), plus the k8s-style sub-paths the deployment
  manifests actually probe: `/actuator/health/readiness` and `/actuator/health/liveness`
  (`management.health.probes.enabled=true`, set locally - see `application.properties`).
- **Metrics**: `micrometer-registry-prometheus` is on the classpath, so `/actuator/prometheus`
  is available the moment `management.endpoints.web.exposure.include` (config-repo, per profile)
  includes `prometheus` - JVM (heap, GC, threads), HTTP server (request count/latency by route
  and status), HikariCP pool, and Tomcat metrics are all exported with zero custom code. No
  custom business metrics (e.g. login success/failure counters) exist yet beyond what's already
  queryable from the audit trail and `LoginAuditEntity` table - a reasonable next increment, not a gap
  blocking deployment.
- **Structured logs**: APPLICATION/ERROR/AUDIT/SECURITY/SQL/ACCESS appenders
  (`logstash-logback-encoder`, JSON, SIEM-ingestible without regex parsing); every line carries
  the correlation id via MDC once one has been minted (login) or presented (an authenticated
  request's JWT).
- **Correlation id propagation (Rule 13)**: minted once at login, reused verbatim on every
  refresh in that session, embedded in the JWT (`correlationId` claim) so the Gateway and every
  downstream service the token reaches can tie their own logs back to the same session -
  `MdcCleanupFilter` guarantees it never leaks onto a later, unrelated request on the same
  pooled thread.
- **API docs**: `/swagger-ui.html` and `/v3/api-docs` (springdoc-openapi) - both public paths,
  but every endpoint they document still requires the same real Bearer token to actually call.

## Production Hardening & Security Checklist

- [x] **Transactional integrity**: every write path carries an explicit, method-level
      `@Transactional(rollbackFor = Exception.class)` - not just Spring's default (unchecked
      exceptions only), so a checked exception from anywhere in the call chain still rolls back
      cleanly instead of silently committing a partial write.
- [x] **No stack traces to the client**: `AuthExceptionHandler`'s catch-all logs the full
      exception internally (keyed by correlation id) and returns a generic message; every
      expected failure mode (duplicate account, bad credentials, locked account, invalid/expired
      token, reused password, malformed JSON body, a `?param=` type mismatch) has its own typed
      handler mapping to the right HTTP status - nothing falls through to a misleading 500.
- [x] **Password handling**: BCrypt (`auth.password-encoder-strength`, default 12), password
      history enforced on register/reset/change (`auth.password-history-limit`), account lockout
      with time-based auto-unlock, reset tokens are opaque + single-use + hashed at rest (raw
      value never persisted, only travels once to the not-yet-built Notification Service).
- [x] **Token handling**: access tokens are short-lived JWTs validated independently by this
      service (never trusts Gateway-forwarded identity headers); refresh tokens are opaque,
      hashed at rest, rotated every use, with reuse detection that revokes the entire session
      family, not just the replayed token.
- [x] **Defense in depth on CORS**: explicit `CorsConfigurationSource` (`auth.allowed-origins`)
      even though the Gateway already enforces its own - this service is independently
      reachable and must not rely solely on an upstream proxy's policy.
- [x] **Explicit security headers**: frame-options deny, content-type-options, cache-control,
      HSTS (365-day max-age, includeSubDomains) - set explicitly rather than relying silently on
      Spring Security's defaults (Rule 14), even where they already match.
- [x] **Pagination capped**: `spring.data.web.pageable.max-page-size=100` - a client-supplied
      `?size=` on `GET /accounts` or `GET /audit` can't force one query to load the whole table.
- [x] **RBAC enforced at the method level**: `@PreAuthorize("hasAuthority('ROLE_ADMIN')")` on
      every admin-only endpoint (`listAccounts`, `lockAccount`, `unlockAccount`, both audit
      endpoints) in addition to the URL-level `authorizeHttpRequests` rule.
- [x] **Rate limiting on public endpoints**: `RateLimitFilter` (Redis-backed, fixed window,
      per-IP-per-path via `ClientIpResolver`) throttles `/register`, `/login`, `/refresh`,
      `/forgot-password`, `/reset-password` at this service's own layer - `auth.rate-limit-max-
      requests` requests per `auth.rate-limit-window-seconds` window, `429` + `Retry-After` once
      exceeded. Runs ahead of `JwtAuthenticationFilter` in the chain and reuses the same Redis
      instance already backing the revoked-jti store, so it scales correctly across replicas
      instead of resetting per-instance like an in-memory counter would. **Fails closed**: if
      Redis is unreachable, the request is rejected with `503 SERVICE_UNAVAILABLE`
      (`DownstreamServiceUnavailableException`) rather than let through unthrottled - Redis is a
      required dependency here, not optional defense in depth. Same treatment for
      `JwtAuthenticationFilter`'s revoked-jti check: a Redis outage now fails the request with the
      same 503 instead of leaking an unhandled exception past Spring MVC.
- [x] **Content-Security-Policy header**: `default-src 'self'; frame-ancestors 'none'` added
      alongside the existing frame-options/content-type-options/HSTS headers.
- [x] **CORS origin parsing fixed**: `auth.allowed-origins` entries are now `.trim()`'d before
      being handed to `CorsConfiguration` - a comma-separated value with spaces (`"a, b"`) used to
      silently fail to match a real `Origin` header.
- [x] **Source-level dependency scanning**: OWASP `dependency-check-maven` (fails the build on any
      CVSS ≥ 7 finding) added to `pom.xml`, invoked as its own Jenkins stage - separate from, and
      complementary to, the existing Trivy **container-image** scan stage.
- [x] **Required integrations fail loud, not silent**: the Audit Log Service and Notification
      Service Feign clients' fallback factories now throw `DownstreamServiceUnavailableException`
      (503) instead of logging a warning and letting the request appear to succeed - see the
      Deployment-Ready Checklist below for exactly which endpoints that blocks until each service
      is actually deployed. Deliberate trade-off, not an oversight: it also means an unreachable
      Notification Service reopens the identifier-existence side channel `forgotPassword`/
      `requestOtp`/`requestContactVerification` otherwise close (unknown identifier still returns
      200 immediately; a known one now returns 503 instead of 200 for as long as the outage
      lasts) - see `NotificationServiceClientFallbackFactory`'s Javadoc.
- [ ] **Not yet implemented - flagged, not glossed over**: no CAPTCHA/bot-detection on public
      endpoints (rate limiting reduces but doesn't eliminate credential-stuffing/enumeration risk);
      the Audit Log Service and Notification Service themselves are still not built - the Feign
      clients, fallbacks, and circuit breakers are real and wired, but until those services exist,
      the endpoints that depend on them fail with 503 by design (see above), not degrade; the
      Gateway/Auth-Service JWT roles-claim key name (`roleTypes` here) has not been reconciled
      with the Gateway's own copy - flagged earlier in this project, still open.

## Performance Tuning

- **Indexes**: every foreign key and every column this service actually filters/sorts/joins on
  has an explicit `@Index` (or is covered by a `@UniqueConstraint`, which also indexes) -
  `publicId`/`email`/`mobileNumber` on `ClickKartUserEntity`, `(ip_address, occurred_at)` composite on
  `LoginAuditEntity` for the brute-force queries, `correlation_id`/`actor`/`occurred_at` on
  `AuditLogEntryEntity`, etc. Nothing here relies on an unindexed sequential scan for a query this
  service issues itself.
- **N+1 avoidance**: `ClickKartUserRepository.findByPublicIdWithRoles` uses an explicit
  `left join fetch` (roles resolved in one round trip) for the one call site - login - that
  needs them immediately; every other read leans on LAZY plus staying inside the same
  transactional method, which is safe here since every service method is itself the transaction
  boundary.
- **Locking is minimal and targeted**: pessimistic writes only where genuinely required for
  correctness under concurrency - the audit chain head (serializes hash-chain appends) and a
  refresh/reset token being consumed (closes the reuse-detection race) - never a broad table or
  row lock on a hot read path.
- **Connection pool / batch settings**: HikariCP pool size, `spring.jpa.properties.hibernate.jdbc.batch_size`,
  and similar tuning knobs are not set explicitly anywhere in this repo - they inherit Spring
  Boot's own defaults (Hikari: 10 connections) unless overridden per-profile in the config-repo.
  Worth revisiting once real qa/prod load-test numbers exist; not a blocker for initial
  deployment at expected Auth Service traffic (comparatively low-volume, short-lived requests).

## Deployment-Ready Checklist

- [x] Builds and runs standalone (Eclipse + Maven); registers with Eureka; pulls all config
      from Config Server across all 4 profiles
- [x] No Flyway/Liquibase (explicit project decision) - `ddl-auto=update` creates/alters the
      schema at boot in every profile; container starts; endpoints reachable through the Gateway
- [x] Zero TODO/stub methods across registration, login/lockout, refresh rotation (with reuse
      detection), logout/revocation, forgot/reset/change password (with password-history
      enforcement), admin account listing/lock/unlock, and the tamper-evident audit trail - all
      real, computed logic
- [x] Feign fallbacks (`AuditLogServiceClientFallbackFactory`, `NotificationServiceClientFallbackFactory`)
      log locally, then throw `DownstreamServiceUnavailableException` (503) - both are required
      dependencies, not best-effort side effects. **Consequence**: until the Audit Log Service and
      Notification Service are actually deployed, every write endpoint (register, login, OTP
      login, refresh, logout, change-password, admin lock/unlock/delete) fails with 503 (Audit Log
      Service dispatch is on every one of them), and forgot-password/OTP-request/verify-contact-
      request additionally require the Notification Service specifically. Same treatment for Redis:
      `RateLimitFilter` and `JwtAuthenticationFilter`'s revocation check now fail closed (503)
      instead of open if Redis is unreachable.
- [x] Every file labeled with its exact path
- [x] API contract matches Rule 12: `/api/v1/auth/**` routes, one `ApiResponse` envelope for
      every response - success or error - across all 12 endpoints, including logout/forgot/reset/
      change-password (200 with `data:null` instead of a bare 204 or 201, so there's no
      endpoint-specific exception to the contract). `AuthController`/`AuditController` build
      success envelopes explicitly; `AuthExceptionHandler` builds every error envelope - same
      shape either way, documented interactively via `/swagger-ui.html`.
- [x] Correlation id minted once at login, carried through refresh, enforced on every other
      endpoint (`MissingCorrelationIdException` → 400)
- [x] No tutorial shortcuts: no exposed stack traces, every expected failure mode has its own
      typed handler and HTTP status, BCrypt password hashing, real optimistic-locked lockout,
      dev-only secrets flagged and fail-fast everywhere else
- [x] Structured logging: APPLICATION/ERROR/AUDIT/SECURITY/SQL/ACCESS appenders, async, size+time
      rotation, correlation id in every line
- [x] Docker image builds and runs; compose base + 4 per-env overrides in place; wired into the
      repo-root `docker-compose.app-tier.yml` / `docker-compose.dev-infra.yml`
- [x] Metrics/health exported for scraping/probing (`/actuator/prometheus` once exposed by the
      config-repo profile, `/actuator/health/{readiness,liveness}` already wired into the k8s
      manifests) - see Observability & Metrics above
- [ ] Known, explicitly-flagged gaps (see Production Hardening checklist above): no
      CAPTCHA/bot-detection at this service's own layer, Notification Service not yet built,
      Gateway roles-claim key naming drift

**Status: Auth Service confirmed deployable**, with the gaps above explicitly flagged rather than
silently assumed away. Next up per the locked build order: User Service.
