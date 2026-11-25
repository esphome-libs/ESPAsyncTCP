#ifndef ASYNC_QUEUED_SEND_H_
#define ASYNC_QUEUED_SEND_H_

#include <memory>
#include <new>

#include "ESPAsyncTCP.h"
#include "cbuf.h"

// Sends as much of a queued buffer as the client takes now and returns the
// byte count. A TLS add() can take less than offered, so only what it took is
// dequeued, before send(), which can tear the client (and the queue) down.
inline size_t asyncTcpSendQueued(AsyncClient *client, cbuf *queue) {
  size_t available = queue->available();
  if (!client->connected() || !client->canSend() || available == 0)
    return 0;
  size_t sendable = client->space();
  if (sendable < available)
    available = sendable;
  // Under heap pressure fall back to smaller chunks so the queue still drains
  std::unique_ptr<char[]> out(new (std::nothrow) char[available]);
  while (!out && available > 64) {
    available /= 2;
    out.reset(new (std::nothrow) char[available]);
  }
  if (!out)
    return 0;
  queue->peek(out.get(), available);
  size_t sent = client->add(out.get(), available);
  if (sent) {
    queue->remove(sent);
    client->send();
  }
  return sent;
}

#endif
