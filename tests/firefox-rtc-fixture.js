"use strict";

const dgram = require("node:dgram");
const net = require("node:net");

// A local RFC 5389 Binding collector. It sends no traffic except replies to
// valid requests received on its own ephemeral socket, and stores no peer IPs.
async function startStunCollector(host = "127.0.0.1") {
  if (net.isIP(host) !== 4) throw new Error("RTC fixture requires a local IPv4 literal");
  const socket = dgram.createSocket("udp4");
  let counts = { packets: 0, bindingRequests: 0, responses: 0, invalidPackets: 0, responseErrors: 0 };
  socket.on("message", (packet, peer) => {
    counts.packets++;
    if (packet.length < 20 || packet.length > 1500 || packet.readUInt16BE(0) !== 0x0001
        || packet.readUInt32BE(4) !== 0x2112a442 || packet.readUInt16BE(2) !== packet.length - 20) {
      counts.invalidPackets++;
      return;
    }
    counts.bindingRequests++;
    const reply = Buffer.alloc(32);
    reply.writeUInt16BE(0x0101, 0); // Binding success, one XOR-MAPPED-ADDRESS.
    reply.writeUInt16BE(12, 2);
    reply.writeUInt32BE(0x2112a442, 4);
    packet.copy(reply, 8, 8, 20);
    reply.writeUInt16BE(0x0020, 20);
    reply.writeUInt16BE(8, 22);
    reply[25] = 1; // IPv4.
    reply.writeUInt16BE(peer.port ^ 0x2112, 26);
    const address = peer.address.split(".").map(Number), cookie = [0x21, 0x12, 0xa4, 0x42];
    for (let index = 0; index < 4; index++) reply[28 + index] = address[index] ^ cookie[index];
    socket.send(reply, peer.port, peer.address, error => {
      if (error) counts.responseErrors++;
      else counts.responses++;
    });
  });
  await new Promise((resolve, reject) => {
    socket.once("error", reject);
    socket.bind(0, host, () => { socket.removeListener("error", reject); resolve(); });
  });
  return {
    host, port: socket.address().port,
    snapshot: () => ({ ...counts }),
    reset: () => { counts = { packets: 0, bindingRequests: 0, responses: 0, invalidPackets: 0, responseErrors: 0 }; },
    close: () => new Promise(resolve => socket.close(resolve)),
  };
}

async function probeRtc(harness, collector, durationMs = 3500) {
  const result = await harness.client.command("WebDriver:ExecuteAsyncScript", {
    script: `
      const config = arguments[0], done = arguments[arguments.length - 1];
      const report = { supported: typeof RTCPeerConnection === "function", candidates: 0,
        hostCandidates: 0, srflxCandidates: 0, relayCandidates: 0,
        literalAddressCandidates: 0, candidateErrors: 0, completed: false };
      if (!report.supported) { done(report); return; }
      let peer, finished = false;
      const finish = () => {
        if (finished) return;
        finished = true;
        report.completed = peer?.iceGatheringState === "complete";
        peer?.close();
        done(report);
      };
      const timer = setTimeout(finish, config.durationMs);
      Promise.resolve().then(async () => {
        peer = new RTCPeerConnection({ iceServers: [{ urls: config.stunUrl }], iceCandidatePoolSize: 0 });
        peer.onicecandidate = event => {
          const candidate = event.candidate;
          if (!candidate) return;
          report.candidates++;
          if (candidate.type === "host") report.hostCandidates++;
          if (candidate.type === "srflx") report.srflxCandidates++;
          if (candidate.type === "relay") report.relayCandidates++;
          const address = candidate.address || "";
          if (/^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$/.test(address) || address.includes(":")) report.literalAddressCandidates++;
        };
        peer.onicecandidateerror = () => { report.candidateErrors++; };
        peer.createDataChannel("isolated-rtc-fixture");
        await peer.setLocalDescription(await peer.createOffer());
      }).catch(error => {
        report.failureCategory = error?.name || "Error";
        clearTimeout(timer);
        finish();
      });
    `,
    args: [{ stunUrl: `stun:${collector.host}:${collector.port}`, durationMs }],
  });
  return result?.value;
}

module.exports = { startStunCollector, probeRtc };
