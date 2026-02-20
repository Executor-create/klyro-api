/*
  Warnings:

  - You are about to drop the column `token` on the `users` table. All the data in the column will be lost.
  - A unique constraint covering the columns `[refreshToken]` on the table `users` will be added. If there are existing duplicate values, this will fail.

*/
-- DropIndex
DROP INDEX "users_token_key";

-- AlterTable
ALTER TABLE "users" DROP COLUMN "token",
ADD COLUMN     "refreshToken" TEXT;

-- CreateIndex
CREATE UNIQUE INDEX "users_refreshToken_key" ON "users"("refreshToken");
