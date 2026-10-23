## Architecture
```
├── .cursor/
│   └── rules/
│       ├── 01-architecture.mdc     # Architecture rules for your AI
│       └── 02-otp-auth.mdc         # Security & business logic constraints
├── src/
│   ├── config/
│   │   ├── database.ts             # pg pool connection configuration
│   │   └── mailer.ts               # SendGrid and Twilio configuration boilerplate
│   ├── controllers/
│   │   └── auth.controller.ts      # HTTP layer: handle request/response
│   ├── middlewares/
│   │   ├── auth.middleware.ts      # JWT Validation check
│   │   └── error.middleware.ts     # Global catch-all error handling
│   ├── models/
│   │   └── user.model.ts           # Postgres SQL execution/Queries
│   ├── routes/
│   │   └── auth.routes.ts          # Express Route definitions
│   ├── services/
│   │   ├── auth.service.ts         # Core business logic: JWT & OTP verification
│   │   └── email.service.ts        # SendGrid abstraction layer
│   │   └── sms.service.ts          # Twilio abstraction layer
│   ├── types/
│   │   └── express.d.ts            # Extension for Request namespaces
│   ├── app.ts                      # Express app configuration
│   └── server.ts                   # App entrypoint & server start
├── .env.example                    # Template for environment secrets
├── package.json
└── tsconfig.json
```
