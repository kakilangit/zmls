//! Ratchet tree node types (LeafNode, ParentNode, Capabilities,
//! Lifetime, Extension) per RFC 9420 Sections 7.1-7.2 with
//! encode/decode.
// Ratchet tree node types for MLS per RFC 9420 Sections 7.1-7.2.
//
// Defines LeafNode, ParentNode, and their supporting types
// (Capabilities, Lifetime, Extension, HPKEPublicKey). The Node
// tagged union wraps either a leaf or parent for tree storage.
//
// All types include encode/decode using the slice-based codec.

const std = @import("std");
const assert = std.debug.assert;
const codec = @import("../codec/codec.zig");
const varint = @import("../codec/varint.zig");
const types = @import("../common/types.zig");
const errors = @import("../common/errors.zig");
const cred_mod = @import("../credential/credential.zig");
const prim = @import("../crypto/primitives.zig");

const EncodeError = codec.EncodeError;
const DecodeError = errors.DecodeError;
const CryptoError = errors.CryptoError;
const ValidationError = errors.ValidationError;
const CredentialType = types.CredentialType;
const CipherSuite = types.CipherSuite;
const ProtocolVersion = types.ProtocolVersion;
const ProposalType = types.ProposalType;
const ExtensionType = types.ExtensionType;
const LeafNodeSource = types.LeafNodeSource;
const LeafIndex = types.LeafIndex;
const Credential = cred_mod.Credential;
const Certificate = cred_mod.Certificate;

/// Maximum number of entries in a capabilities list.
const max_list_len: u32 = 256;
/// Maximum extension data size in bytes.
const max_extension_data: u32 = 65535;
/// Maximum number of extensions per node.
const max_extensions: u32 = 64;
/// Maximum encryption/signature key size.
const max_key_len: u32 = 256;
/// Maximum signature size.
const max_sig_len: u32 = 256;
/// Maximum unmerged leaves in a parent node.
const max_unmerged: u32 = 65535;
/// Maximum parent hash size.
const max_hash_len: u32 = 256;

/// Maximum buffer size for encoding a LeafNodeTBS (with context).
/// Generous upper bound: keys + cred + caps + lifetime + extensions
/// + group_id + leaf_index.
pub const max_leaf_encode: u32 = 8192;

// -- Extension ---------------------------------------------------------------

/// A generic TLS-style extension.
///
///   struct {
///       ExtensionType extension_type;
///       opaque extension_data<V>;
///   } Extension;
pub const Extension = struct {
    extension_type: ExtensionType,
    data: []const u8,

    pub fn encode(
        self: *const Extension,
        buf: []u8,
        pos: u32,
    ) EncodeError!u32 {
        var p = try codec.encodeUint16(
            buf,
            pos,
            @intFromEnum(self.extension_type),
        );
        p = try codec.encodeVarVector(buf, p, self.data);
        return p;
    }

    pub fn decode(
        allocator: std.mem.Allocator,
        data: []const u8,
        pos: u32,
    ) (DecodeError || error{OutOfMemory})!struct {
        value: Extension,
        pos: u32,
    } {
        const type_r = try codec.decodeUint16(data, pos);
        const ext_type: ExtensionType = @enumFromInt(
            type_r.value,
        );
        const data_r = try codec.decodeVarVectorLimited(
            allocator,
            data,
            type_r.pos,
            types.max_extension_data_length,
        );
        return .{
            .value = .{
                .extension_type = ext_type,
                .data = data_r.value,
            },
            .pos = data_r.pos,
        };
    }

    pub fn deinit(
        self: *Extension,
        allocator: std.mem.Allocator,
    ) void {
        if (self.data.len > 0) {
            allocator.free(self.data);
        }
        self.data = &.{};
        self.* = undefined;
    }

    /// Deep-copy this extension. Caller owns the returned value.
    pub fn clone(
        self: *const Extension,
        allocator: std.mem.Allocator,
    ) error{OutOfMemory}!Extension {
        const data_copy = if (self.data.len > 0)
            try cloneSlice(u8, allocator, self.data)
        else
            @as([]const u8, &.{});
        return .{
            .extension_type = self.extension_type,
            .data = data_copy,
        };
    }
};

// -- Capabilities ------------------------------------------------------------

/// Capabilities advertised by a leaf node.
///
///   struct {
///       ProtocolVersion versions<V>;
///       CipherSuite cipher_suites<V>;
///       ExtensionType extensions<V>;
///       ProposalType proposals<V>;
///       CredentialType credentials<V>;
///   } Capabilities;
pub const Capabilities = struct {
    versions: []const ProtocolVersion,
    cipher_suites: []const CipherSuite,
    extensions: []const ExtensionType,
    proposals: []const ProposalType,
    credentials: []const CredentialType,

    pub fn encode(
        self: *const Capabilities,
        buf: []u8,
        pos: u32,
    ) EncodeError!u32 {
        var p = pos;
        p = try encodeEnumList(u16, buf, p, self.versions);
        p = try encodeEnumList(u16, buf, p, self.cipher_suites);
        p = try encodeEnumList(u16, buf, p, self.extensions);
        p = try encodeEnumList(u16, buf, p, self.proposals);
        p = try encodeEnumList(u16, buf, p, self.credentials);
        return p;
    }

    pub fn decode(
        allocator: std.mem.Allocator,
        data: []const u8,
        pos: u32,
    ) (DecodeError || error{OutOfMemory})!struct {
        value: Capabilities,
        pos: u32,
    } {
        var p = pos;
        const ver_r = try decodeEnumList(
            ProtocolVersion,
            u16,
            allocator,
            data,
            p,
        );
        errdefer freeSlice(ProtocolVersion, allocator, ver_r.value);
        p = ver_r.pos;
        const cs_r = try decodeEnumList(
            CipherSuite,
            u16,
            allocator,
            data,
            p,
        );
        errdefer freeSlice(CipherSuite, allocator, cs_r.value);
        p = cs_r.pos;
        const ext_r = try decodeEnumList(
            ExtensionType,
            u16,
            allocator,
            data,
            p,
        );
        errdefer freeSlice(ExtensionType, allocator, ext_r.value);
        p = ext_r.pos;
        const prop_r = try decodeEnumList(
            ProposalType,
            u16,
            allocator,
            data,
            p,
        );
        errdefer freeSlice(ProposalType, allocator, prop_r.value);
        p = prop_r.pos;
        const cred_r = try decodeEnumList(
            CredentialType,
            u16,
            allocator,
            data,
            p,
        );
        p = cred_r.pos;

        return .{
            .value = .{
                .versions = ver_r.value,
                .cipher_suites = cs_r.value,
                .extensions = ext_r.value,
                .proposals = prop_r.value,
                .credentials = cred_r.value,
            },
            .pos = p,
        };
    }

    pub fn deinit(
        self: *Capabilities,
        allocator: std.mem.Allocator,
    ) void {
        freeSlice(ProtocolVersion, allocator, self.versions);
        freeSlice(CipherSuite, allocator, self.cipher_suites);
        freeSlice(ExtensionType, allocator, self.extensions);
        freeSlice(ProposalType, allocator, self.proposals);
        freeSlice(CredentialType, allocator, self.credentials);
        self.* = undefined;
    }

    /// Deep-copy this capabilities struct.
    pub fn clone(
        self: *const Capabilities,
        allocator: std.mem.Allocator,
    ) error{OutOfMemory}!Capabilities {
        const vers = try cloneSlice(
            ProtocolVersion,
            allocator,
            self.versions,
        );
        errdefer freeSlice(ProtocolVersion, allocator, vers);
        const cs = try cloneSlice(
            CipherSuite,
            allocator,
            self.cipher_suites,
        );
        errdefer freeSlice(CipherSuite, allocator, cs);
        const exts = try cloneSlice(
            ExtensionType,
            allocator,
            self.extensions,
        );
        errdefer freeSlice(ExtensionType, allocator, exts);
        const props = try cloneSlice(
            ProposalType,
            allocator,
            self.proposals,
        );
        errdefer freeSlice(ProposalType, allocator, props);
        const creds = try cloneSlice(
            CredentialType,
            allocator,
            self.credentials,
        );
        return .{
            .versions = vers,
            .cipher_suites = cs,
            .extensions = exts,
            .proposals = props,
            .credentials = creds,
        };
    }
};

// -- Lifetime ----------------------------------------------------------------

/// Validity window for a leaf node sourced from a KeyPackage.
///
///   struct { uint64 not_before; uint64 not_after; } Lifetime;
pub const Lifetime = struct {
    not_before: u64,
    not_after: u64,

    pub fn encode(
        self: *const Lifetime,
        buf: []u8,
        pos: u32,
    ) EncodeError!u32 {
        var p = try codec.encodeUint64(
            buf,
            pos,
            self.not_before,
        );
        p = try codec.encodeUint64(buf, p, self.not_after);
        return p;
    }

    pub fn decode(
        data: []const u8,
        pos: u32,
    ) DecodeError!struct { value: Lifetime, pos: u32 } {
        const nb_r = try codec.decodeUint64(data, pos);
        const na_r = try codec.decodeUint64(data, nb_r.pos);
        return .{
            .value = .{
                .not_before = nb_r.value,
                .not_after = na_r.value,
            },
            .pos = na_r.pos,
        };
    }
};

// -- LeafNode ----------------------------------------------------------------

/// A leaf in the ratchet tree. Per RFC 9420 Section 7.2.
///
///   struct {
///       HPKEPublicKey encryption_key;
///       SignaturePublicKey signature_key;
///       Credential credential;
///       Capabilities capabilities;
///       LeafNodeSource leaf_node_source;
///       select (LeafNode.leaf_node_source) {
///           case key_package: Lifetime lifetime;
///           case update: (empty)
///           case commit: opaque parent_hash<V>;
///       };
///       Extension extensions<V>;
///       opaque signature<V>;
///   } LeafNode;
pub const LeafNode = struct {
    encryption_key: []const u8,
    signature_key: []const u8,
    credential: Credential,
    capabilities: Capabilities,
    source: LeafNodeSource,
    /// Only set when source == .key_package.
    lifetime: ?Lifetime,
    /// Only set when source == .commit. Per RFC 9420 Section 7.2.
    parent_hash: ?[]const u8,
    extensions: []const Extension,
    signature: []const u8,

    // -- Encode (full signed LeafNode) --

    pub fn encode(
        self: *const LeafNode,
        buf: []u8,
        pos: u32,
    ) EncodeError!u32 {
        assert(self.encryption_key.len > 0);
        var p = try self.encodeTbs(buf, pos);
        // signature<V>.
        p = try codec.encodeVarVector(buf, p, self.signature);
        return p;
    }

    /// Encode the to-be-signed portion (everything except signature).
    ///
    /// This is the base TBS without group context fields. Used for
    /// wire encoding and for key_package source signing.
    pub fn encodeTbs(
        self: *const LeafNode,
        buf: []u8,
        pos: u32,
    ) EncodeError!u32 {
        var p = pos;
        // encryption_key<V>.
        p = try codec.encodeVarVector(buf, p, self.encryption_key);
        // signature_key<V>.
        p = try codec.encodeVarVector(buf, p, self.signature_key);
        // credential.
        p = try self.credential.encode(buf, p);
        // capabilities.
        p = try self.capabilities.encode(buf, p);
        // leaf_node_source (u8).
        p = try codec.encodeUint8(
            buf,
            p,
            @intFromEnum(self.source),
        );
        // source-specific fields.
        if (self.source == .key_package) {
            // RFC §7.2: Lifetime is structurally required for
            // key_package source. The decoder always reads it,
            // so the encoder must always write it.
            const lt = self.lifetime orelse
                return error.MissingLifetime;
            p = try lt.encode(buf, p);
        } else if (self.source == .commit) {
            // parent_hash<V> per RFC 9420 Section 7.2.
            const ph = self.parent_hash orelse &.{};
            p = try codec.encodeVarVector(buf, p, ph);
        }
        // extensions<V> — varint-prefixed list of Extension.
        p = try encodeExtensionList(buf, p, self.extensions);
        return p;
    }

    /// Encode the full LeafNodeTBS for signing per RFC 9420 Section 7.2.
    ///
    /// For update/commit sources, appends group_id<V> and uint32
    /// leaf_index after the base TBS. For key_package source, the
    /// base TBS is used as-is (no context fields).
    pub fn encodeSignContent(
        self: *const LeafNode,
        buf: []u8,
        pos: u32,
        group_id: ?[]const u8,
        leaf_index: ?LeafIndex,
    ) EncodeError!u32 {
        var p = try self.encodeTbs(buf, pos);
        // Append context for update/commit sources.
        if (self.source == .update or self.source == .commit) {
            const gid = group_id orelse
                return error.BufferTooSmall;
            const li = leaf_index orelse
                return error.BufferTooSmall;
            p = try codec.encodeVarVector(buf, p, gid);
            p = try codec.encodeUint32(buf, p, li.toU32());
        }
        return p;
    }

    /// Sign this LeafNode. Fills in self.signature.
    ///
    /// For update/commit sources, group_id and leaf_index are
    /// required (appended to TBS per RFC 9420 Section 7.2).
    /// For key_package source, they must be null.
    pub fn signLeafNode(
        self: *LeafNode,
        comptime P: type,
        sk: *const [P.sign_sk_len]u8,
        sig_buf: *[P.sig_len]u8,
        group_id: ?[]const u8,
        leaf_index: ?LeafIndex,
    ) (EncodeError || CryptoError)!void {
        var tbs_buf: [max_leaf_encode]u8 = undefined;
        const tbs_end = try self.encodeSignContent(
            &tbs_buf,
            0,
            group_id,
            leaf_index,
        );
        const sig = try prim.signWithLabel(
            P,
            sk,
            "LeafNodeTBS",
            tbs_buf[0..tbs_end],
        );
        sig_buf.* = sig;
        self.signature = sig_buf;
    }

    /// Verify the signature on this LeafNode.
    ///
    /// For update/commit sources, group_id and leaf_index are
    /// required. For key_package source, they must be null.
    pub fn verifyLeafNodeSignature(
        self: *const LeafNode,
        comptime P: type,
        group_id: ?[]const u8,
        leaf_index: ?LeafIndex,
    ) (EncodeError || CryptoError)!void {
        if (self.signature_key.len != P.sign_pk_len) {
            return error.InvalidPublicKey;
        }
        const pk: *const [P.sign_pk_len]u8 = @ptrCast(
            self.signature_key[0..P.sign_pk_len],
        );
        if (self.signature.len == 0) {
            return error.SignatureVerifyFailed;
        }
        var tbs_buf: [max_leaf_encode]u8 = undefined;
        const tbs_end = try self.encodeSignContent(
            &tbs_buf,
            0,
            group_id,
            leaf_index,
        );
        try prim.verifyWithLabel(
            P,
            pk,
            "LeafNodeTBS",
            tbs_buf[0..tbs_end],
            self.signature,
        );
    }

    // -- Validate (RFC 9420 Section 7.3) --

    /// Validate a LeafNode's internal consistency per RFC 9420
    /// Section 7.3.
    ///
    /// Checks:
    ///   1. The leaf's credential type is listed in its own
    ///      capabilities.credentials.
    ///   2. The group cipher suite is listed in the leaf's
    ///      capabilities.cipher_suites.
    ///   3. Every extension present in the leaf's extensions
    ///      list is advertised in capabilities.extensions.
    pub fn validate(
        self: *const LeafNode,
        expected_suite: CipherSuite,
        current_time: ?u64,
    ) ValidationError!void {
        // 1. Credential type must be in capabilities.
        const cred_type = self.credential.tag;
        if (!capsContains(
            CredentialType,
            self.capabilities.credentials,
            cred_type,
        )) {
            return error.InvalidLeafNode;
        }

        // 1b. capabilities.versions MUST include mls10
        //     (RFC 9420 §7.2).
        if (!capsContains(
            ProtocolVersion,
            self.capabilities.versions,
            .mls10,
        )) {
            return error.InvalidLeafNode;
        }

        // 2. Cipher suite must be in capabilities.
        if (!capsContains(
            CipherSuite,
            self.capabilities.cipher_suites,
            expected_suite,
        )) {
            return error.InvalidLeafNode;
        }

        // 3. Non-default extensions must be in capabilities.
        //    Default extension types (1-5) are implicitly
        //    supported per RFC 9420 Section 7.2.
        for (self.extensions) |ext| {
            const v = @intFromEnum(ext.extension_type);
            if (v >= 1 and v <= 5) continue;
            if (!capsContains(
                ExtensionType,
                self.capabilities.extensions,
                ext.extension_type,
            )) {
                return error.InvalidLeafNode;
            }
        }

        // 4. capabilities.proposals MUST NOT list default
        //    proposal types (1-7) per RFC 9420 Section 7.2.
        for (self.capabilities.proposals) |pt| {
            const v = @intFromEnum(pt);
            if (v >= 1 and v <= 7)
                return error.InvalidLeafNode;
        }

        // 5. capabilities.extensions MUST NOT list default
        //    extension types (1-5) per RFC 9420 Section 7.2.
        for (self.capabilities.extensions) |et| {
            const v = @intFromEnum(et);
            if (v >= 1 and v <= 5)
                return error.InvalidLeafNode;
        }

        // 6. Lifetime check (when time source is available).
        if (current_time) |now| {
            if (self.lifetime) |lt| {
                if (now < lt.not_before or now > lt.not_after)
                    return error.InvalidLeafNode;
            }
        }

        // 7. If required_capabilities extension present, the leaf's
        //    own capabilities must satisfy it (RFC 9420 S7.3).
        try self.validateSelfRequiredCaps();
    }

    /// Validate that encryption_key is a valid HPKE public
    /// key for the cipher suite per RFC 9420 §7.3. Requires
    /// crypto provider access.
    pub fn validateEncryptionKey(
        self: *const LeafNode,
        comptime P: type,
    ) (ValidationError || CryptoError)!void {
        if (self.encryption_key.len != P.npk)
            return error.InvalidPublicKey;
        P.validateDhPublicKey(
            self.encryption_key[0..P.npk],
        ) catch return error.InvalidPublicKey;
    }

    /// Check that any required_capabilities extension on this leaf
    /// is satisfied by the leaf's own capabilities.
    fn validateSelfRequiredCaps(
        self: *const LeafNode,
    ) ValidationError!void {
        for (self.extensions) |ext| {
            if (ext.extension_type != .required_capabilities)
                continue;
            const data = ext.data;
            // Parse three var-vectors of u16 values.
            const ext_r = codec.decodeVarVectorSlice(
                data,
                0,
            ) catch return error.InvalidLeafNode;
            const prop_r = codec.decodeVarVectorSlice(
                data,
                ext_r.pos,
            ) catch return error.InvalidLeafNode;
            const cred_r = codec.decodeVarVectorSlice(
                data,
                prop_r.pos,
            ) catch return error.InvalidLeafNode;
            // Each required extension type must be in caps.
            try checkReqU16(
                ExtensionType,
                ext_r.value,
                self.capabilities.extensions,
            );
            try checkReqU16(
                ProposalType,
                prop_r.value,
                self.capabilities.proposals,
            );
            try checkReqU16(
                CredentialType,
                cred_r.value,
                self.capabilities.credentials,
            );
            return;
        }
    }

    // -- Decode --

    const SourceFields = struct {
        lifetime: ?Lifetime,
        parent_hash: ?[]const u8,
        pos: u32,
    };

    /// Decode leaf_node_source and its per-variant fields.
    fn decodeSourceFields(
        allocator: std.mem.Allocator,
        data: []const u8,
        pos: u32,
    ) (DecodeError || error{OutOfMemory})!SourceFields {
        const src_r = try codec.decodeUint8(data, pos);
        const source: LeafNodeSource = @enumFromInt(
            src_r.value,
        );
        const p = src_r.pos;

        switch (source) {
            .key_package => {
                const lt_r = try Lifetime.decode(data, p);
                return .{
                    .lifetime = lt_r.value,
                    .parent_hash = null,
                    .pos = lt_r.pos,
                };
            },
            .update => return .{
                .lifetime = null,
                .parent_hash = null,
                .pos = p,
            },
            .commit => {
                const ph_r = try codec.decodeVarVectorLimited(
                    allocator,
                    data,
                    p,
                    types.max_hash_length,
                );
                return .{
                    .lifetime = null,
                    .parent_hash = ph_r.value,
                    .pos = ph_r.pos,
                };
            },
            else => return error.InvalidEnumValue,
        }
    }

    const IdentityFields = struct {
        encryption_key: []const u8,
        signature_key: []const u8,
        credential: Credential,
        capabilities: Capabilities,
        pos: u32,
    };

    /// Decode the identity fields of a LeafNode:
    /// encryption_key, signature_key, credential, capabilities.
    fn decodeIdentityFields(
        allocator: std.mem.Allocator,
        data: []const u8,
        pos: u32,
    ) (DecodeError || error{OutOfMemory})!IdentityFields {
        var p = pos;

        const ek_r = try codec.decodeVarVectorLimited(
            allocator,
            data,
            p,
            types.max_public_key_length,
        );
        errdefer allocator.free(ek_r.value);
        p = ek_r.pos;

        const sk_r = try codec.decodeVarVectorLimited(
            allocator,
            data,
            p,
            types.max_public_key_length,
        );
        errdefer allocator.free(sk_r.value);
        p = sk_r.pos;

        const cred_r = try Credential.decode(
            allocator,
            data,
            p,
        );
        errdefer {
            var c = cred_r.value;
            c.deinit(allocator);
        }
        p = cred_r.pos;

        const caps_r = try Capabilities.decode(
            allocator,
            data,
            p,
        );
        p = caps_r.pos;

        return .{
            .encryption_key = ek_r.value,
            .signature_key = sk_r.value,
            .credential = cred_r.value,
            .capabilities = caps_r.value,
            .pos = p,
        };
    }

    pub fn decode(
        allocator: std.mem.Allocator,
        data: []const u8,
        pos: u32,
    ) (DecodeError || error{OutOfMemory})!struct {
        value: LeafNode,
        pos: u32,
    } {
        const id = try decodeIdentityFields(
            allocator,
            data,
            pos,
        );
        errdefer {
            allocator.free(id.encryption_key);
            allocator.free(id.signature_key);
            var cred = id.credential;
            cred.deinit(allocator);
            var caps = id.capabilities;
            caps.deinit(allocator);
        }
        var p = id.pos;
        const src_r = try decodeSourceFields(
            allocator,
            data,
            p,
        );
        errdefer if (src_r.parent_hash) |ph|
            allocator.free(ph);
        p = src_r.pos;
        const ext_r = try decodeExtensionList(
            allocator,
            data,
            p,
        );
        errdefer {
            freeDecodedExts(
                allocator,
                @constCast(ext_r.value),
            );
            allocator.free(ext_r.value);
        }
        p = ext_r.pos;
        const sig_r = try codec.decodeVarVectorLimited(
            allocator,
            data,
            p,
            types.max_signature_length,
        );

        const source: LeafNodeSource =
            if (src_r.lifetime != null) .key_package else if (src_r.parent_hash != null) .commit else .update;

        return .{ .value = .{
            .encryption_key = id.encryption_key,
            .signature_key = id.signature_key,
            .credential = id.credential,
            .capabilities = id.capabilities,
            .source = source,
            .lifetime = src_r.lifetime,
            .parent_hash = src_r.parent_hash,
            .extensions = @as(
                []const Extension,
                ext_r.value,
            ),
            .signature = sig_r.value,
        }, .pos = sig_r.pos };
    }

    pub fn deinit(
        self: *LeafNode,
        allocator: std.mem.Allocator,
    ) void {
        if (self.encryption_key.len > 0) {
            prim.secureZeroConst(self.encryption_key);
            allocator.free(self.encryption_key);
        }
        if (self.signature_key.len > 0) {
            prim.secureZeroConst(self.signature_key);
            allocator.free(self.signature_key);
        }
        self.credential.deinit(allocator);
        self.capabilities.deinit(allocator);
        if (self.parent_hash) |ph| {
            if (ph.len > 0) allocator.free(ph);
        }
        for (self.extensions) |*ext| {
            @constCast(ext).deinit(allocator);
        }
        if (self.extensions.len > 0) {
            allocator.free(self.extensions);
        }
        if (self.signature.len > 0) {
            allocator.free(self.signature);
        }
        self.* = undefined;
    }

    /// Deep-copy this leaf node. Caller owns the returned value.
    pub fn clone(
        self: *const LeafNode,
        allocator: std.mem.Allocator,
    ) error{OutOfMemory}!LeafNode {
        const ek = try cloneSliceOrEmpty(allocator, self.encryption_key);
        errdefer if (ek.len > 0) allocator.free(ek);
        const sk = try cloneSliceOrEmpty(allocator, self.signature_key);
        errdefer if (sk.len > 0) allocator.free(sk);
        var cred = try self.credential.clone(allocator);
        errdefer cred.deinit(allocator);
        var caps = try self.capabilities.clone(allocator);
        errdefer caps.deinit(allocator);
        const ph: ?[]const u8 = if (self.parent_hash) |p|
            (if (p.len > 0) try cloneSlice(u8, allocator, p) else @as([]const u8, &.{}))
        else
            null;
        errdefer if (ph) |p| {
            if (p.len > 0) allocator.free(p);
        };
        const exts = try cloneExtensions(allocator, self.extensions);
        errdefer freeExtensions(allocator, exts);
        const sig = try cloneSliceOrEmpty(allocator, self.signature);
        return .{
            .encryption_key = ek,
            .signature_key = sk,
            .credential = cred,
            .capabilities = caps,
            .source = self.source,
            .lifetime = self.lifetime,
            .parent_hash = ph,
            .extensions = exts,
            .signature = sig,
        };
    }
};

// -- ParentNode --------------------------------------------------------------

/// An intermediate node in the ratchet tree.
///
///   struct {
///       HPKEPublicKey encryption_key;
///       opaque parent_hash<V>;
///       uint32 unmerged_leaves<V>;
///   } ParentNode;
pub const ParentNode = struct {
    encryption_key: []const u8,
    parent_hash: []const u8,
    unmerged_leaves: []const LeafIndex,

    pub fn encode(
        self: *const ParentNode,
        buf: []u8,
        pos: u32,
    ) EncodeError!u32 {
        var p = pos;
        p = try codec.encodeVarVector(
            buf,
            p,
            self.encryption_key,
        );
        p = try codec.encodeVarVector(
            buf,
            p,
            self.parent_hash,
        );
        // unmerged_leaves<V> as varint-prefixed u32 list.
        p = try encodeU32List(buf, p, self.unmerged_leaves);
        return p;
    }

    pub fn decode(
        allocator: std.mem.Allocator,
        data: []const u8,
        pos: u32,
    ) (DecodeError || error{OutOfMemory})!struct {
        value: ParentNode,
        pos: u32,
    } {
        var p = pos;
        const ek_r = try codec.decodeVarVectorLimited(
            allocator,
            data,
            p,
            types.max_public_key_length,
        );
        errdefer allocator.free(ek_r.value);
        p = ek_r.pos;

        const ph_r = try codec.decodeVarVectorLimited(
            allocator,
            data,
            p,
            types.max_hash_length,
        );
        errdefer allocator.free(ph_r.value);
        p = ph_r.pos;

        const ul_r = try decodeU32List(allocator, data, p);
        p = ul_r.pos;

        return .{
            .value = .{
                .encryption_key = ek_r.value,
                .parent_hash = ph_r.value,
                .unmerged_leaves = ul_r.value,
            },
            .pos = p,
        };
    }

    pub fn deinit(
        self: *ParentNode,
        allocator: std.mem.Allocator,
    ) void {
        if (self.encryption_key.len > 0) {
            prim.secureZeroConst(self.encryption_key);
            allocator.free(self.encryption_key);
        }
        if (self.parent_hash.len > 0) {
            allocator.free(self.parent_hash);
        }
        if (self.unmerged_leaves.len > 0) {
            allocator.free(self.unmerged_leaves);
        }
        self.* = undefined;
    }

    /// Deep-copy this parent node. Caller owns the returned value.
    pub fn clone(
        self: *const ParentNode,
        allocator: std.mem.Allocator,
    ) error{OutOfMemory}!ParentNode {
        const ek = try cloneSliceOrEmpty(
            allocator,
            self.encryption_key,
        );
        errdefer if (ek.len > 0) allocator.free(ek);
        const ph = try cloneSliceOrEmpty(
            allocator,
            self.parent_hash,
        );
        errdefer if (ph.len > 0) allocator.free(ph);
        const ul = if (self.unmerged_leaves.len > 0)
            try cloneSlice(
                LeafIndex,
                allocator,
                self.unmerged_leaves,
            )
        else
            @as([]const LeafIndex, &.{});
        return .{
            .encryption_key = ek,
            .parent_hash = ph,
            .unmerged_leaves = ul,
        };
    }
};

// -- Node (optional wrapper) -------------------------------------------------

/// A position in the ratchet tree: either a leaf, a parent, or blank.
///
/// Per RFC 9420 Section 7.1: the ratchet tree is an array of
/// optional<Node> entries.
pub const NodeType = enum(u8) {
    leaf = 1,
    parent = 2,
};

pub const Node = struct {
    node_type: NodeType,
    payload: NodePayload,

    pub const NodePayload = union {
        leaf: LeafNode,
        parent: ParentNode,
    };

    pub fn initLeaf(leaf: LeafNode) Node {
        return .{
            .node_type = .leaf,
            .payload = .{ .leaf = leaf },
        };
    }

    pub fn initParent(parent: ParentNode) Node {
        return .{
            .node_type = .parent,
            .payload = .{ .parent = parent },
        };
    }

    /// Encode a Node (type byte + payload).
    pub fn encode(
        self: *const Node,
        buf: []u8,
        pos: u32,
    ) EncodeError!u32 {
        var p = try codec.encodeUint8(
            buf,
            pos,
            @intFromEnum(self.node_type),
        );
        switch (self.node_type) {
            .leaf => {
                p = try self.payload.leaf.encode(buf, p);
            },
            .parent => {
                p = try self.payload.parent.encode(buf, p);
            },
        }
        return p;
    }

    /// Decode a Node (type byte + payload).
    pub fn decode(
        allocator: std.mem.Allocator,
        data: []const u8,
        pos: u32,
    ) (DecodeError || error{OutOfMemory})!struct {
        value: Node,
        pos: u32,
    } {
        const type_r = try codec.decodeUint8(data, pos);
        const node_type: NodeType = switch (type_r.value) {
            1 => .leaf,
            2 => .parent,
            else => return error.InvalidEnumValue,
        };

        switch (node_type) {
            .leaf => {
                const leaf_r = try LeafNode.decode(
                    allocator,
                    data,
                    type_r.pos,
                );
                return .{
                    .value = Node.initLeaf(leaf_r.value),
                    .pos = leaf_r.pos,
                };
            },
            .parent => {
                const parent_r = try ParentNode.decode(
                    allocator,
                    data,
                    type_r.pos,
                );
                return .{
                    .value = Node.initParent(parent_r.value),
                    .pos = parent_r.pos,
                };
            },
        }
    }

    pub fn deinit(
        self: *Node,
        allocator: std.mem.Allocator,
    ) void {
        switch (self.node_type) {
            .leaf => self.payload.leaf.deinit(allocator),
            .parent => self.payload.parent.deinit(allocator),
        }
        self.* = undefined;
    }

    /// Deep-copy this node. Caller owns the returned value.
    pub fn clone(
        self: *const Node,
        allocator: std.mem.Allocator,
    ) error{OutOfMemory}!Node {
        switch (self.node_type) {
            .leaf => {
                const leaf = try self.payload.leaf.clone(
                    allocator,
                );
                return Node.initLeaf(leaf);
            },
            .parent => {
                const parent = try self.payload.parent.clone(
                    allocator,
                );
                return Node.initParent(parent);
            },
        }
    }
};

// -- Codec helpers for lists -------------------------------------------------

/// Encode a slice of enum values as a varint-prefixed vector of u16s.
fn encodeEnumList(
    comptime IntType: type,
    buf: []u8,
    pos: u32,
    items: anytype,
) EncodeError!u32 {
    const item_size: u32 = @sizeOf(IntType);
    if (items.len > types.max_vec_length / item_size)
        return error.BufferTooSmall;
    const byte_len: u32 = @intCast(items.len * item_size);
    var p = try varint.encode(buf, pos, byte_len);
    for (items) |item| {
        const val: IntType = @intFromEnum(item);
        if (IntType == u16) {
            p = try codec.encodeUint16(buf, p, val);
        } else if (IntType == u8) {
            p = try codec.encodeUint8(buf, p, val);
        } else {
            @compileError("unsupported enum int type");
        }
    }
    return p;
}

/// Decode a varint-prefixed vector of u16 enum values.
fn decodeEnumList(
    comptime E: type,
    comptime IntType: type,
    allocator: std.mem.Allocator,
    data: []const u8,
    pos: u32,
) (DecodeError || error{OutOfMemory})!struct {
    value: []const E,
    pos: u32,
} {
    const item_size: u32 = @sizeOf(IntType);
    const vr = try varint.decode(data, pos);
    const byte_len = vr.value;
    var p = vr.pos;

    if (byte_len > types.max_vec_length) {
        return error.VectorTooLarge;
    }
    if (byte_len % item_size != 0) return error.Truncated;
    const count = byte_len / item_size;
    if (count > max_list_len) return error.VectorTooLarge;
    if (p + byte_len > data.len) return error.Truncated;

    const items = allocator.alloc(
        E,
        count,
    ) catch return error.OutOfMemory;
    errdefer allocator.free(items);

    for (items, 0..) |*item, i| {
        _ = i;
        if (IntType == u16) {
            const r = try codec.decodeUint16(data, p);
            item.* = @enumFromInt(r.value);
            p = r.pos;
        } else if (IntType == u8) {
            const r = try codec.decodeUint8(data, p);
            item.* = @enumFromInt(r.value);
            p = r.pos;
        }
    }

    return .{ .value = items, .pos = p };
}

/// Encode extensions as a varint-prefixed vector.
pub fn encodeExtensionList(
    buf: []u8,
    pos: u32,
    exts: []const Extension,
) EncodeError!u32 {
    return codec.encodeVarPrefixedList(
        Extension,
        buf,
        pos,
        exts,
    );
}

/// Decode extensions from a varint-prefixed vector.
/// Free extension data slices allocated during decode.
fn freeDecodedExts(
    allocator: std.mem.Allocator,
    exts: []Extension,
) void {
    for (exts) |ext| allocator.free(ext.data);
}

pub fn decodeExtensionList(
    allocator: std.mem.Allocator,
    data: []const u8,
    pos: u32,
) (DecodeError || error{OutOfMemory})!struct {
    value: []Extension,
    pos: u32,
} {
    const vr = try varint.decode(data, pos);
    const total_len = vr.value;
    var p = vr.pos;

    if (total_len > types.max_vec_length) {
        return error.VectorTooLarge;
    }
    if (p + total_len > data.len) return error.Truncated;

    const end = p + total_len;
    var temp: [max_extensions]Extension = undefined;
    var count: u32 = 0;

    errdefer freeDecodedExts(allocator, temp[0..count]);
    while (p < end) {
        if (count >= max_extensions) {
            return error.VectorTooLarge;
        }
        const ext_r = try Extension.decode(allocator, data, p);
        temp[count] = ext_r.value;
        count += 1;
        p = ext_r.pos;
    }

    if (p != end) return error.Truncated;

    // RFC 9420 S13.4: reject duplicate extension types.
    var di: u32 = 0;
    while (di < count) : (di += 1) {
        var dj: u32 = di + 1;
        while (dj < count) : (dj += 1) {
            if (temp[di].extension_type ==
                temp[dj].extension_type)
            {
                return error.DuplicateExtensionType;
            }
        }
    }

    const exts = allocator.alloc(
        Extension,
        count,
    ) catch return error.OutOfMemory;
    @memcpy(exts, temp[0..count]);

    return .{ .value = exts, .pos = p };
}

/// Encode a slice of LeafIndex as varint-prefixed u32 list.
fn encodeU32List(
    buf: []u8,
    pos: u32,
    items: []const LeafIndex,
) EncodeError!u32 {
    if (items.len > types.max_vec_length / 4)
        return error.BufferTooSmall;
    const byte_len: u32 = @intCast(items.len * 4);
    var p = try varint.encode(buf, pos, byte_len);
    for (items) |item| {
        p = try codec.encodeUint32(buf, p, item.toU32());
    }
    return p;
}

/// Decode a varint-prefixed u32 list into a slice of LeafIndex.
fn decodeU32List(
    allocator: std.mem.Allocator,
    data: []const u8,
    pos: u32,
) (DecodeError || error{OutOfMemory})!struct {
    value: []const LeafIndex,
    pos: u32,
} {
    const vr = try varint.decode(data, pos);
    const byte_len = vr.value;
    var p = vr.pos;

    if (byte_len > types.max_vec_length) {
        return error.VectorTooLarge;
    }
    if (byte_len % 4 != 0) return error.Truncated;
    const count = byte_len / 4;
    if (p + byte_len > data.len) return error.Truncated;

    const items = allocator.alloc(
        LeafIndex,
        count,
    ) catch return error.OutOfMemory;
    errdefer allocator.free(items);

    for (items) |*item| {
        const r = try codec.decodeUint32(data, p);
        item.* = LeafIndex.fromU32(r.value);
        p = r.pos;
    }

    return .{ .value = items, .pos = p };
}

/// Free an allocated slice if non-empty.
fn freeSlice(
    comptime T: type,
    allocator: std.mem.Allocator,
    slice: []const T,
) void {
    if (slice.len > 0) {
        allocator.free(slice);
    }
}

/// Allocate a copy of a slice. Caller owns the returned slice.
fn cloneSlice(
    comptime T: type,
    allocator: std.mem.Allocator,
    src: []const T,
) error{OutOfMemory}![]const T {
    const dst = allocator.alloc(
        T,
        src.len,
    ) catch return error.OutOfMemory;
    @memcpy(dst, src);
    return dst;
}

/// Clone a u8 slice, returning empty literal for zero-length.
fn cloneSliceOrEmpty(
    allocator: std.mem.Allocator,
    src: []const u8,
) error{OutOfMemory}![]const u8 {
    if (src.len > 0) {
        return cloneSlice(u8, allocator, src);
    }
    return &.{};
}

/// Deep-clone an extension list.
pub fn cloneExtensions(
    allocator: std.mem.Allocator,
    exts: []const Extension,
) error{OutOfMemory}![]const Extension {
    if (exts.len == 0) return &.{};
    const dst = allocator.alloc(
        Extension,
        exts.len,
    ) catch return error.OutOfMemory;
    var i: u32 = 0;
    errdefer {
        var j: u32 = 0;
        while (j < i) : (j += 1) {
            dst[j].deinit(allocator);
        }
        allocator.free(dst);
    }
    while (i < exts.len) : (i += 1) {
        dst[i] = try exts[i].clone(allocator);
    }
    return dst;
}

/// Free a cloned extension list.
fn freeExtensions(
    allocator: std.mem.Allocator,
    exts: []const Extension,
) void {
    for (exts) |*ext| {
        @constCast(ext).deinit(allocator);
    }
    if (exts.len > 0) {
        allocator.free(exts);
    }
}

// -- Helpers -----------------------------------------------------------------

/// Check if a value is present in a capabilities list.
fn capsContains(
    comptime T: type,
    list: []const T,
    needle: T,
) bool {
    for (list) |v| {
        if (v == needle) return true;
    }
    return false;
}

/// Check that every u16 value in `req_bytes` (serialized var-vector
/// of u16 values) appears in `supported` (enum slice).
fn checkReqU16(
    comptime E: type,
    req_bytes: []const u8,
    supported: []const E,
) ValidationError!void {
    if (req_bytes.len % 2 != 0)
        return error.InvalidLeafNode;
    var i: u32 = 0;
    while (i + 1 < req_bytes.len) : (i += 2) {
        const val: u16 = @as(u16, req_bytes[i]) << 8 |
            @as(u16, req_bytes[i + 1]);
        const required: E = @enumFromInt(val);
        var found = false;
        for (supported) |s| {
            if (s == required) {
                found = true;
                break;
            }
        }
        if (!found) return error.InvalidLeafNode;
    }
}

// -- GREASE injection (moved from common/grease.zig to fix layer violation) --

const grease_mod = @import("../common/grease.zig");

/// Append one GREASE value to each capability list (extensions,
/// proposals, credentials). Returns a new Capabilities whose
/// arrays are heap-allocated. Caller must call `deinitGreased`
/// to free the injected arrays.
pub fn injectGrease(
    allocator: std.mem.Allocator,
    caps: *const Capabilities,
) error{OutOfMemory}!Capabilities {
    const exts = try appendOneEnum(
        ExtensionType,
        allocator,
        caps.extensions,
        grease_mod.grease_extension,
    );
    errdefer allocator.free(exts);
    const props = try appendOneEnum(
        ProposalType,
        allocator,
        caps.proposals,
        grease_mod.grease_proposal,
    );
    errdefer allocator.free(props);
    const creds = try appendOneEnum(
        CredentialType,
        allocator,
        caps.credentials,
        grease_mod.grease_credential,
    );
    return .{
        .versions = caps.versions,
        .cipher_suites = caps.cipher_suites,
        .extensions = exts,
        .proposals = props,
        .credentials = creds,
    };
}

/// Free arrays allocated by `injectGrease`.
pub fn deinitGreased(
    allocator: std.mem.Allocator,
    caps: *Capabilities,
) void {
    assert(caps.extensions.len > 0);
    assert(caps.proposals.len > 0);
    assert(caps.credentials.len > 0);
    allocator.free(caps.extensions);
    allocator.free(caps.proposals);
    allocator.free(caps.credentials);
    caps.* = undefined;
}

/// Append a single value to an existing slice, returning a
/// new heap-allocated slice. If the value already exists in
/// the slice, returns a duplicate without the extra element.
fn appendOneEnum(
    comptime T: type,
    allocator: std.mem.Allocator,
    existing: []const T,
    value: T,
) error{OutOfMemory}![]const T {
    for (existing) |item| {
        if (@intFromEnum(item) == @intFromEnum(value)) {
            return allocator.dupe(T, existing);
        }
    }
    const new = try allocator.alloc(T, existing.len + 1);
    @memcpy(new[0..existing.len], existing);
    new[existing.len] = value;
    return new;
}
