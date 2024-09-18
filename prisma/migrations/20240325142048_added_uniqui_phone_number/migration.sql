/*
  Warnings:

  - A unique constraint covering the columns `[phone_number]` on the table `sms_codes` will be added. If there are existing duplicate values, this will fail.

*/
-- CreateIndex
CREATE UNIQUE INDEX "sms_codes_phone_number_key" ON "sms_codes"("phone_number");
