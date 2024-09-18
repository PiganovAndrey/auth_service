/*
  Warnings:

  - You are about to drop the `mail_verificate_codes` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropTable
DROP TABLE "mail_verificate_codes";

-- CreateTable
CREATE TABLE "mail_codes" (
    "id" SERIAL NOT NULL,
    "mail" TEXT NOT NULL,
    "code" TEXT NOT NULL,

    CONSTRAINT "mail_codes_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "mail_codes_mail_key" ON "mail_codes"("mail");
