/*
  Warnings:

  - You are about to drop the column `createdAt` on the `otps` table. All the data in the column will be lost.
  - You are about to drop the column `expiresAt` on the `otps` table. All the data in the column will be lost.
  - You are about to drop the column `updatedAt` on the `otps` table. All the data in the column will be lost.
  - You are about to drop the column `userId` on the `otps` table. All the data in the column will be lost.
  - You are about to drop the column `createdAt` on the `users` table. All the data in the column will be lost.
  - You are about to drop the column `refreshToken` on the `users` table. All the data in the column will be lost.
  - You are about to drop the column `updatedAt` on the `users` table. All the data in the column will be lost.
  - A unique constraint covering the columns `[refresh_token]` on the table `users` will be added. If there are existing duplicate values, this will fail.
  - Added the required column `expires_at` to the `otps` table without a default value. This is not possible if the table is not empty.
  - Added the required column `user_id` to the `otps` table without a default value. This is not possible if the table is not empty.

*/
-- DropForeignKey
ALTER TABLE "otps" DROP CONSTRAINT "otps_userId_fkey";

-- DropIndex
DROP INDEX "users_refreshToken_key";

-- AlterTable
ALTER TABLE "otps" DROP COLUMN "createdAt",
DROP COLUMN "expiresAt",
DROP COLUMN "updatedAt",
DROP COLUMN "userId",
ADD COLUMN     "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
ADD COLUMN     "expires_at" TIMESTAMP(3) NOT NULL,
ADD COLUMN     "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
ADD COLUMN     "user_id" TEXT NOT NULL;

-- AlterTable
ALTER TABLE "users" DROP COLUMN "createdAt",
DROP COLUMN "refreshToken",
DROP COLUMN "updatedAt",
ADD COLUMN     "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
ADD COLUMN     "refresh_token" TEXT,
ADD COLUMN     "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP;

-- CreateIndex
CREATE UNIQUE INDEX "users_refresh_token_key" ON "users"("refresh_token");

-- AddForeignKey
ALTER TABLE "otps" ADD CONSTRAINT "otps_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
