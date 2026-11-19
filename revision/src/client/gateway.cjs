"use strict";
const fs = require("node:fs"),
  crypto = require("node:crypto"),
  grpc = require("@grpc/grpc-js");
const { connect, signers, hash } = require("@hyperledger/fabric-gateway");
const { gateway: gp, peer, common } = require("@hyperledger/fabric-protos");
const { ClientIdentity } = require("fabric-shim");
const C = require("../shared/canonical.cjs"),
  { POLICY: P } = require("../shared/policy.cjs");
function principalFromCertificate(mspId, certificate) {
  const cid = new ClientIdentity({
    getChannelID: () => "",
    getTxID: () => "",
    getCreator: () => ({ mspid: mspId, idBytes: Buffer.from(certificate) }),
  });
  return { mspId: cid.getMSPID(), clientIdentityId: cid.getID() };
}
function inspectReleaseProposal(bytes, challenge) {
  const proposed = gp.ProposedTransaction.deserializeBinary(bytes),
    signed = proposed.getProposal();
  if (!signed) C.fail("SIGNED_RELEASE_PROPOSAL_REQUIRED");
  const proposal = peer.Proposal.deserializeBinary(
    signed.getProposalBytes_asU8(),
  );
  const header = common.Header.deserializeBinary(proposal.getHeader_asU8());
  const channel = common.ChannelHeader.deserializeBinary(
    header.getChannelHeader_asU8(),
  );
  const payload = peer.ChaincodeProposalPayload.deserializeBinary(
    proposal.getPayload_asU8(),
  );
  if (payload.getTransientmapMap().getLength())
    C.fail("RELEASE_TRANSIENT_FORBIDDEN");
  const invocation = peer.ChaincodeInvocationSpec.deserializeBinary(
      payload.getInput_asU8(),
    ),
    spec = invocation.getChaincodeSpec(),
    args = spec
      ?.getInput()
      ?.getArgsList()
      .map((b) => Buffer.from(b).toString("utf8"));
  if (
    channel.getChannelId() !== challenge.context.channelId ||
    spec?.getChaincodeId()?.getName() !== P.chaincodeName ||
    !args ||
    args.length !== 2 ||
    args[0] !== "BFDRevision:getReleaseAuthorization" ||
    !C.equal(C.parseStrict(args[1]), challenge)
  )
    C.fail("RELEASE_PROPOSAL_BINDING");
  return proposed;
}
function openGateway(config) {
  C.fields(
    config,
    [
      "mspId",
      "certificatePath",
      "privateKeyPath",
      "tlsRootPath",
      "endpoint",
      "channel",
    ],
    ["serverName"],
  );
  C.text(config.mspId);
  C.text(config.channel);
  C.text(config.endpoint);
  const certificate = fs.readFileSync(config.certificatePath),
    key = crypto.createPrivateKey(fs.readFileSync(config.privateKeyPath));
  const signer = signers.newPrivateKeySigner(key),
    options = config.serverName
      ? {
          "grpc.ssl_target_name_override": config.serverName,
          "grpc.default_authority": config.serverName,
        }
      : {};
  const client = new grpc.Client(
    config.endpoint,
    grpc.credentials.createSsl(fs.readFileSync(config.tlsRootPath)),
    options,
  );
  const connection = connect({
    client,
    identity: { mspId: config.mspId, credentials: certificate },
    signer,
    hash: hash.sha256,
    evaluateOptions: () => ({ deadline: Date.now() + 10000 }),
    endorseOptions: () => ({ deadline: Date.now() + 20000 }),
    submitOptions: () => ({ deadline: Date.now() + 10000 }),
    commitStatusOptions: () => ({ deadline: Date.now() + 60000 }),
  });
  const contract = connection
    .getNetwork(config.channel)
    .getContract(P.chaincodeName, "BFDRevision");
  return {
    principal: principalFromCertificate(config.mspId, certificate),
    context: {
      profile: P.profile,
      channelId: config.channel,
      chaincodeName: P.chaincodeName,
    },
    async query(method, input) {
      return C.parseStrict(
        Buffer.from(
          await contract.evaluateTransaction(method, C.canonical(input)),
        ).toString("utf8"),
        P.maxLedgerBytes * 4,
      );
    },
    async submit(method, input) {
      const pending = await contract.submitAsync(method, {
        arguments: [C.canonical(input)],
      });
      const status = await pending.getStatus();
      if (!status.successful) {
        const e = Error("FABRIC_COMMIT_INVALID:" + status.code);
        e.validationCode = status.code;
        e.transactionId = status.transactionId;
        throw e;
      }
      return {
        value: C.parseStrict(
          Buffer.from(pending.getResult()).toString("utf8"),
          P.maxLedgerBytes * 4,
        ),
        commit: {
          successful: true,
          validationCode: status.code,
          transactionId: status.transactionId,
          blockNumber: String(status.blockNumber),
        },
      };
    },
    async signReleaseChallenge(challenge) {
      if (
        !C.equal(challenge.granteePrincipal, this.principal) ||
        !C.equal(challenge.context, this.context)
      )
        C.fail("RELEASE_CLIENT_BINDING");
      const proposal = contract.newProposal("getReleaseAuthorization", {
        arguments: [C.canonical(challenge)],
      });
      return {
        challenge,
        proposalBytes: Buffer.from(proposal.getBytes()).toString("base64"),
        signature: Buffer.from(await signer(proposal.getDigest())).toString(
          "base64",
        ),
      };
    },
    async authenticateRelease(proof, challenge) {
      C.fields(proof, ["challenge", "proposalBytes", "signature"]);
      if (!C.equal(proof.challenge, challenge))
        C.fail("RELEASE_CHALLENGE_MISMATCH");
      const bytes = C.base64(proof.proposalBytes);
      if (bytes.length > P.maxLedgerBytes) C.fail("RELEASE_PROPOSAL_SIZE");
      inspectReleaseProposal(bytes, challenge);
      const signature = C.base64(proof.signature);
      const result = C.parseStrict(
        Buffer.from(
          await connection.newSignedProposal(bytes, signature).evaluate(),
        ).toString("utf8"),
      );
      C.fields(result, ["challenge", "principal", "assurance"]);
      if (
        result.assurance !== "AUTHENTICATED_RELEASE_QUERY" ||
        !C.equal(result.challenge, challenge) ||
        !C.equal(result.principal, challenge.granteePrincipal)
      )
        C.fail("RELEASE_PEER_AUTHORIZATION");
      return result.principal;
    },
    close() {
      connection.close();
      client.close();
    },
  };
}
module.exports = {
  openGateway,
  inspectReleaseProposal,
  principalFromCertificate,
};
