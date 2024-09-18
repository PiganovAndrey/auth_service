-- CreateTable
CREATE TABLE "sms_codes" (
    "id" SERIAL NOT NULL,
    "phone_number" TEXT NOT NULL,
    "sms_code" TEXT NOT NULL,

    CONSTRAINT "sms_codes_pkey" PRIMARY KEY ("id")
);
