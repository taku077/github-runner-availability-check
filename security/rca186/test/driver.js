// LOCAL SYNTHETIC TEST ENTRY ONLY. Never deploy this file.
export { Checkpoint } from "../src/worker.js";
export default {
  async fetch(request, env) {
    const path = new URL(request.url).pathname;
    const stub = env.CHECKPOINT.get(env.CHECKPOINT.idFromName("public-synthetic-fixture"));
    if (request.method === "GET" && path === "/fixture/state") return Response.json(await stub.current());
    if (request.method === "POST" && path === "/fixture/cas") {
      const v = await request.json();
      return Response.json(await stub.advance(v.expected, v.previous, v.next));
    }
    return new Response("NOT_ENABLED",{status:403});
  }
};
