-- CreateTable
CREATE TABLE "mail_verificate_codes" (
    "id" SERIAL NOT NULL,
    "mail" TEXT NOT NULL,
    "code" TEXT NOT NULL,

    CONSTRAINT "mail_verificate_codes_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "mail_verificate_codes_mail_key" ON "mail_verificate_codes"("mail");
