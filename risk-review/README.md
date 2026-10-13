# IAM risk review

I reviewed the roles that were already written. I am not approving them.

The deployment role is rejected because it allows `ssm:SendCommand` with `AWS-RunShellScript` and `AWS-RunPowerShellScript`, so the pipeline can run any command on the server. It is also rejected because S3 get and put are allowed on every bucket, and because the role can change the tags that limit which servers it may touch. The account id has 11 digits, and one S3 name has a leading space, so those two lines will not match what they are meant to match.

The database roles are rejected because `rds:*` only controls the RDS service in AWS. It does not give `SELECT`, `INSERT`, `UPDATE`, or `DELETE` inside the database. Admin and CRUB can still damage the database server. ReadOnly can describe RDS and still cannot read rows.

To fix the deployment role, allow one reviewed SSM document and one deployment bucket, and take away permission to edit those tags. To fix the database roles, give each person `rds-db:connect` as their own database user, then grant ReadOnly only `SELECT`, CRUB only select/insert/update/delete, and Admin only the schema changes that job needs.