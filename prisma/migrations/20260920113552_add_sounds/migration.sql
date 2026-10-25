-- CreateTable
CREATE TABLE "Sound" (
    "id" SERIAL NOT NULL,
    "name" TEXT NOT NULL,
    "fileName" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "userId" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Sound_pkey" PRIMARY KEY ("id")
);

-- AddForeignKey
ALTER TABLE "Sound" ADD CONSTRAINT "Sound_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
