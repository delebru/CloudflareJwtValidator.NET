# Cloudflare JWT Validator

[![Nuget](https://img.shields.io/nuget/v/CloudflareJwtValidator.svg)](https://www.nuget.org/packages/CloudflareJwtValidator)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL%203.0-yellow.svg)](https://opensource.org/license/gpl-3-0)
[![Build](https://github.com/delebru/CloudflareJwtValidator.NET/actions/workflows/build.yml/badge.svg)](https://github.com/delebru/CloudflareJwtValidator.NET/actions/workflows/build.yml)

Middleware for simple JWT (JSON Web Token) validation on web apps behind Cloudflare Zero Trust. This middleware will ensure requests to the web app are sent by Cloudflare by validating the token signature under the `Cf-Access-Jwt-Assertion` header, and ensure the `Cf-Access-Authenticated-User-Email` user email matches the token's user email. 

Source code and documentation: https://github.com/delebru/CloudflareJwtValidator.NET