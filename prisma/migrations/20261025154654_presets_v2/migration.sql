-- AlterTable
ALTER TABLE "Preset" ADD COLUMN     "favorite" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
ADD COLUMN     "usedCount" INTEGER NOT NULL DEFAULT 0;

-- AlterTable
ALTER TABLE "Recording" ADD COLUMN     "durationSec" INTEGER,
ADD COLUMN     "mode" TEXT,
ADD COLUMN     "sizeBytes" INTEGER;

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "calibration" JSONB;
