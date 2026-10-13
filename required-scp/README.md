# Region policy

region-restriction.json is a service control policy for AWS Organizations.

It denies regional API calls when the region is not eu-west-1 (Ireland). A call that would create or describe something in another region is blocked, even if the person's IAM role allows it. The same call in eu-west-1 is still allowed when IAM allows it.

IAM, Route 53, CloudFront, billing, and STS are not denied. Those are global, or they are needed for normal account work. The list is in NotAction in the JSON file.

This policy does not grant access. It only sets a limit. It does not apply to the management account.

Try it on a test OU before attaching it anywhere else. If something important breaks, detach that policy from the OU.