"""Tools administration — inspect and control the lifecycle of normalized Tools (M1-Tools-v1).

A Tool is one callable operation of a Connector, projected from the Connector's promoted
`connector_version` (CONNECTOR_ENGINE §5, ADR-0028). This domain owns the *administrative* surface:
list Tools, retrieve a Tool, and the per-Tool **enable/disable** lifecycle control (FR-CE-4). It is
NOT an importer, normalizer, or executor — the Connector Engine produces Tools; the Runtime
consumes the enabled ones, and this domain only reads their metadata and flips the
`enabled` flag. It never touches a Connection, a Credential, or the decrypt path.
"""
