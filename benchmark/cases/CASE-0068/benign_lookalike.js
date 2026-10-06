function renderMockedResponse(res, mockResponse) {
  // mockResponse is always a plain object constructed synchronously by
  // this module's own test harness (e.g. { body: "...", statusCode: 200 }),
  // never a real HTTP-library network callback argument -- there is no
  // failure path here that could ever make it undefined.
  res.write(mockResponse.body);
  return res.end();
}

module.exports = { renderMockedResponse };
