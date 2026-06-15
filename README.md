# Tarpaulin Course Management Service

A cloud-native, RESTful backend engine designed to manage educational course structures, student enrollments, and user media profiles. Built using Python and Flask, the service is engineered for horizontal scale on Google Cloud Platform, leveraging GCP Datastore for structured NoSQL persistence and Google Cloud Storage for binary asset handling.

The platform enforces rigid, security-first enterprise compliance via public-key cryptography (RS256 JWT validation) and a programmatic Role-Based Access Control (RBAC) security matrix.

## Core Architectural System Capabilities

* **Asymmetric Identity Verification:** Implements custom OAuth2 middleware that intercepts incoming requests, fetches public JSON Web Key Sets (JWKS) via an external Auth0 provider, and verifies asymmetric RS256 signed JWTs natively.
* **Granular Multi-Tenant Security (RBAC):** Restricts downstream execution dynamically based on verified token identity claims (`sub`). Programmatically segregates operational domains across `Admin`, `Instructor`, and `Student` roles.
* **Hybrid Cloud Storage Engine:** Decouples transactional data properties from heavy media streams. Structured records flow through GCP Datastore entities, while binary objects (user avatars) are managed asynchronously via Google Cloud Storage buckets utilizing buffered I/O streams (`io.BytesIO`).
* **Transactional Integrity in NoSQL:** Implements strict data sanity workflows, relationship mapping validations, and conflict prevention mechanisms (e.g., handling overlapping mutation rules on HTTP `PATCH` requests during high-concurrency student updates).

---

## Technical Stack Architecture

* **Application Framework:** Python, Flask
* **Infrastructure Hosting:** Google Cloud App Engine
* **Persistence Layer:** Google Cloud Datastore (NoSQL Object Database)
* **Object Storage:** Google Cloud Storage (GCS Blob Buckets)
* **Security & Identity Framework:** Auth0, Public-Key Infrastructure (PKI), `jose` (JWT), `authlib`

---

## REST API Specification & Security Matrix

All secure resources demand an `Authorization: Bearer <JWT>` payload utilizing signed tokens.

| Endpoint | HTTP Method | Required Role | Execution Function |
| :--- | :--- | :--- | :--- |
| `/users/login` | `POST` | Public | Submits credentials to exchange for an Identity Provider ID Token. |
| `/users` | `GET` | `Admin` | Performs collection scan to return full global user registry. |
| `/users/<id>` | `GET` | `Self` / `Admin` | Inspects target profile; dynamically appends localized hypermedia links (`self`) based on role. |
| `/users/<id>/avatar` | `POST` | `Self` | Accepts binary image streams, uploads directly to Google Cloud Storage. |
| `/users/<id>/avatar` | `GET` | `Self` | Streams byte-arrays out of cloud storage buckets using specified `image/png` mimetypes. |
| `/users/<id>/avatar` | `DELETE` | `Self` | Purges media assets safely out of downstream storage buckets. |
| `/courses` | `POST` | `Admin` | Evaluates instructor validity and generates structured course entities. |
| `/courses` | `GET` | Public | Delivers courses via server-side cursors using query window offsets. |
| `/courses/<id>` | `PATCH` | `Admin` | Implements partial-resource delta updates while protecting immutability requirements. |
| `/courses/<id>/students`| `PATCH` | `Instructor` / `Admin` | Atomically applies bulk student additions/removals while detecting schema conflicts. |

---

## Production Security Operations & Validation Flow

The application explicitly avoids trusting third-party verification wrappers, running defensive runtime token parsing directly within the middleware tier:

1. Establishes defensive runtime boundaries checking for format inconsistencies or missing `Authorization` parameters.
2. Contacts the trusted external identity boundary provider to parse signing parameters (`jwks.json`).
3. Decodes payload properties while confirming expiration lifecycles (`ExpiredSignatureError`) and application target audiences (`JWTClaimsError`).
