# Caddy Knock Knock

A *simple enough but secure for someone* auth schema for caddy reverse proxies.

Basically, you can forbid access to services until a particular, secret parameter is added to the service's URL. Then a session cookie authorizes the access until the tab/browser is closed.

You must be aware that this secret parameter is **equivalent to a token and must be protected as a secret**. Don't create a bookmark in the browser. Keep it safe.

And yes, in the future I will add a timeout, not just "forever". But it's a good POC for now.

## Building

```bash
xcaddy build --with github.com/proofrock/caddy_knockknock@v0.1.2
```

## Configuration

First of all, decide a key and hash it with argon2, for example using [this site](https://argon2.online) (it doesn't seem to send your key over the internet at the time of writing, but check yourself!)

> Example:<br/>
> key: abcdef<br/>
> hash: $argon2id$v=19$m=16,t=2,p=1$Y2lhb2dlcm0$llGztGLqY/nSR2ax5vCtIg

Then, suppose you have a site to protect in caddy:

> Example<br/><https://protected.example.com>

You add a parameter `kkkey` with the secret:

> Example:<br/><https://protected.example.com?kkkey=abcdef>

When you do so, your session will be enabled for <https://protected.example.com>.

This is the corresponding `Caddyfile`:

```caddyfile
{
 order caddy_knockknock first
}

protected.example.com {
  caddy_knockknock {
    key_hash "$argon2id$v=19$m=16,t=2,p=1$Y2lhb2dlcm0$llGztGLqY/nSR2ax5vCtIg"
  }
  respond "Authorized!"
}
```
