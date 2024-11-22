# Caddy Knock Knock

A *simple enough but secure for someone* auth schema for caddy reverse proxies.

Basically, you can forbid access to services until a particular, secret address is visited. Then the visiting IP gains access to the services until caddy is restarted.

You must be aware that this URL is **equivalent to a token and must be protected as a secret**. Don't create a bookmark in the browser. Keep it safe, really.

Also, the IP should be fairly non-shared and non-spoofable. **Avoid VPNs and public WiFi**!

And yes, in the future I will add a timeout, not just "forever". But it's a good POC for now.

## Building

```bash
xcaddy build --with github.com/proofrock/caddy_knockknock@v0.0.1
```

## Configuration

First of all, decide a key and hash it with argon2, for example using [this site](https://argon2.online) (it doesn't seem to send your key over the internet at the time of writing, but check yourself!)

> Example:<br/>
> key: abcdef<br/>
> hash: $argon2id$v=19$m=16,t=2,p=1$Y2lhb2dlcm0$llGztGLqY/nSR2ax5vCtIg

Then, suppose you have a site to protect in caddy:

> Example<br/>https://protected.example.com

You define a "keyhole" site, to call with the key as the path:

> Example:<br/>https://keyhole.example.com/abcdef

When you do so, your IP will be enabled for https://protected.example.com.

This is the corresponding `Caddyfile`:

```caddyfile
{
	order caddy_knockknock first
}

protected.example.com {
  caddy_knockknock
  reverse_proxy mysecretservice:12345
}

keyhole.example.com {
  caddy_knockknock {
    key_hole true
    key_hash "$argon2id$v=19$m=16,t=2,p=1$Y2lhb2dlcm0$llGztGLqY/nSR2ax5vCtIg"
  }
  respond "IP Authorized!"
}
```

And that's all. The empty config in the first endpoint implies `key_hole false`, i.e. that endpoint is just protected. 

`key_hole true` indicates that the 2nd endpoint is the one used to authorize, and a `key_hash` must be provided.
