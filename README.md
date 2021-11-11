# Example C# Validation Caching

This is an example of how to perform validation response caching in C# and .NET.

This example will perform a license validation request, verify its response signature,
and cache the response to the file system. Upon the next invocation, the cache data
will be retrieved and cryptographically verified before being used. Verifying cache
data ensures that the data has not been tampered with.

Other response data can be cached, such as listing a license's entitlements, a licenses's
machine relationship data, etc. All API responses are signed.

## Running the example

First, install dependencies with [`dotnet`](https://docs.microsoft.com/en-us/dotnet/core/tools/dotnet):

```
dotnet restore
```

Then run the program:

```
dotnet run
```

Upon first invocation, you should see the following log output:

```
[INFO] [GetCache] Cache miss: key=validate
[INFO] [SetCache] Cache write: key=validate
[INFO] [Main] License is valid! detail=is valid code=VALID
```

Upon subsequent invocation, you should see the following:

```
[INFO] [GetCache] Cache hit: key=validate
[INFO] [Main] License is valid! detail=is valid code=VALID
```

## Questions?

Reach out at [support@keygen.sh](mailto:support@keygen.sh) if you have any
questions or concerns!
