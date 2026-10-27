export default {
  async fetch(request) {
    const url = new URL(request.url);
    const targetUrl = `https://discord.com${url.pathname}${url.search}`;
    const newRequest = new Request(targetUrl, request);
    return fetch(newRequest);
  }
};