# Security Specification — OK Ajuda

## 1. Data Invariants
1. Every document in `/status_records/{recordId}` must have a valid `recordId` (`^[a-zA-Z0-9_\-]+$`, max 128 chars).
2. Every document in `/status_records/{recordId}` must be owned by an authenticated user with `email_verified == true`, and `ownerId` must strictly equal `request.auth.uid`.
3. `ownerId` and `createdAt` are immutable upon update.
4. `createdAt` must equal `request.time` on `create`, and `updatedAt` must equal `request.time` on both `create` and `update`.
5. `allow list` on `/status_records/{recordId}` strictly enforces `resource.data.ownerId == request.auth.uid`.
6. Every string property enforces strict minimum and maximum character length bounds matching `firebase-blueprint.json`.

## 2. The "Dirty Dozen" Payloads
1. **Unauthenticated Write**: `request.auth == null` attempting `create` on `/status_records/rec1` -> `PERMISSION_DENIED`.
2. **Unverified Email Write**: `request.auth.token.email_verified == false` attempting `create` -> `PERMISSION_DENIED`.
3. **Identity Spoofing on Create**: `ownerId: "victim-uid"` when `request.auth.uid == "attacker-uid"` -> `PERMISSION_DENIED`.
4. **Shadow Field Injection on Create**: Payload includes `"isAdmin": true` not in `hasOnly` allowlist -> `PERMISSION_DENIED`.
5. **Missing Required Field**: Payload omits `responsabilidade` -> `PERMISSION_DENIED`.
6. **Invalid Enum for `tipoProposta`**: `tipoProposta: "invalido"` instead of `"em_andamento"` or `"cancelada"` -> `PERMISSION_DENIED`.
7. **Invalid Enum for `necessarioAtuacao`**: `necessarioAtuacao: "Talvez"` instead of `"Sim"`, `"Não"`, or `"Acompanhar"` -> `PERMISSION_DENIED`.
8. **Oversized String Denial of Wallet**: `significado` with 5,000 characters (exceeds maxLength 2000) -> `PERMISSION_DENIED`.
9. **ID Poisoning**: Document ID containing spaces or special characters (`rec$123!`) -> `PERMISSION_DENIED`.
10. **Immutable Field Mutation on Update**: Changing `ownerId` or `createdAt` during an update -> `PERMISSION_DENIED`.
11. **Forged Client Timestamp**: `createdAt` or `updatedAt` not equal to `request.time` -> `PERMISSION_DENIED`.
12. **Unauthorized Cross-User List/Get**: User A querying `/status_records` belonging to User B -> `PERMISSION_DENIED`.
