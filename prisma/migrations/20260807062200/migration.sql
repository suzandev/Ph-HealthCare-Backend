/*
  Warnings:

  - The values [googleId] on the enum `authProvider` will be removed. If these variants are still used in the database, this will fail.

*/
-- AlterEnum
BEGIN;
CREATE TYPE "authProvider_new" AS ENUM ('GOOGLE', 'CREDENTIAL');
ALTER TABLE "public"."users" ALTER COLUMN "authProvider" DROP DEFAULT;
ALTER TABLE "users" ALTER COLUMN "authProvider" TYPE "authProvider_new" USING ("authProvider"::text::"authProvider_new");
ALTER TYPE "authProvider" RENAME TO "authProvider_old";
ALTER TYPE "authProvider_new" RENAME TO "authProvider";
DROP TYPE "public"."authProvider_old";
ALTER TABLE "users" ALTER COLUMN "authProvider" SET DEFAULT 'CREDENTIAL';
COMMIT;
