# Prisma commands
generate:
	npx prisma generate

migrate-dev:
	npx prisma migrate dev

migrate:
	npx prisma migrate dev --name $(n)

# Application commands
start:
	yarn run start:dev

start-prod:
	yarn run start:prod

build:
	yarn run build