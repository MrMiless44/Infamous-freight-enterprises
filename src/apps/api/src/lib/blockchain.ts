/**
 * Blockchain Integration
 * Immutable shipment records on blockchain
 * Smart contracts for proof of delivery
 * Ethereum/Polygon support
 */

import { ethers } from "ethers";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

/**
 * Blockchain configuration
 */
const BLOCKCHAIN_CONFIG = {
  network: process.env.BLOCKCHAIN_NETWORK || "polygon",
  rpcUrl: process.env.BLOCKCHAIN_RPC_URL || "https://polygon-rpc.com",
  contractAddress: process.env.SHIPMENT_CONTRACT_ADDRESS || "",
  privateKey: process.env.BLOCKCHAIN_PRIVATE_KEY || "",
};

/**
 * Shipment smart contract ABI
 */
const SHIPMENT_CONTRACT_ABI = [
  "function createShipment(string trackingNumber, string origin, string destination, uint256 weight) public returns (uint256)",
  "function updateShipmentStatus(uint256 shipmentId, string status, uint256 timestamp) public",
  "function confirmDelivery(uint256 shipmentId, string signature, uint256 timestamp) public",
  "function getShipment(uint256 shipmentId) public view returns (tuple(string trackingNumber, string origin, string destination, uint256 weight, string status, uint256 createdAt, uint256 deliveredAt, string signature))",
  "event ShipmentCreated(uint256 indexed shipmentId, string trackingNumber, address indexed customer)",
  "event ShipmentUpdated(uint256 indexed shipmentId, string status, uint256 timestamp)",
  "event ShipmentDelivered(uint256 indexed shipmentId, string signature, uint256 timestamp)",
];

/**
 * Blockchain manager
 */
export class BlockchainManager {
  private provider: ethers.providers.JsonRpcProvider;
  private wallet: ethers.Wallet;
  private contract: ethers.Contract;

  constructor() {
    this.provider = new ethers.providers.JsonRpcProvider(
      BLOCKCHAIN_CONFIG.rpcUrl,
    );
    this.wallet = new ethers.Wallet(
      BLOCKCHAIN_CONFIG.privateKey,
      this.provider,
    );
    this.contract = new ethers.Contract(
      BLOCKCHAIN_CONFIG.contractAddress,
      SHIPMENT_CONTRACT_ABI,
      this.wallet,
    );
  }

  /**
   * Create shipment on blockchain
   */
  async createShipment(data: {
    trackingNumber: string;
    origin: string;
    destination: string;
    weight: number;
  }): Promise<{ txHash: string; shipmentId: number }> {
    try {
      console.log(
        `📦 Creating shipment ${data.trackingNumber} on blockchain...`,
      );

      const tx = await this.contract.createShipment(
        data.trackingNumber,
        data.origin,
        data.destination,
        Math.floor(data.weight),
      );

      const receipt = await tx.wait();

      // Extract shipment ID from event
      const event = receipt.events?.find(
        (e: any) => e.event === "ShipmentCreated",
      );
      const shipmentId = event?.args?.shipmentId?.toNumber() || 0;

      console.log(
        `✅ Shipment created on blockchain: ${receipt.transactionHash}`,
      );

      // Store blockchain reference in database
      await prisma.blockchainTransaction.create({
        data: {
          txHash: receipt.transactionHash,
          blockNumber: receipt.blockNumber,
          type: "SHIPMENT_CREATED",
          trackingNumber: data.trackingNumber,
          gasUsed: receipt.gasUsed.toString(),
          status: "confirmed",
        },
      });

      return {
        txHash: receipt.transactionHash,
        shipmentId,
      };
    } catch (error) {
      console.error("Blockchain create shipment error:", error);
      throw new Error("Failed to create shipment on blockchain");
    }
  }

  /**
   * Update shipment status on blockchain
   */
  async updateShipmentStatus(
    shipmentId: number,
    status: string,
    trackingNumber: string,
  ): Promise<string> {
    try {
      console.log(
        `📝 Updating shipment ${trackingNumber} status to ${status} on blockchain...`,
      );

      const timestamp = Math.floor(Date.now() / 1000);
      const tx = await this.contract.updateShipmentStatus(
        shipmentId,
        status,
        timestamp,
      );
      const receipt = await tx.wait();

      console.log(
        `✅ Status updated on blockchain: ${receipt.transactionHash}`,
      );

      await prisma.blockchainTransaction.create({
        data: {
          txHash: receipt.transactionHash,
          blockNumber: receipt.blockNumber,
          type: "STATUS_UPDATED",
          trackingNumber,
          gasUsed: receipt.gasUsed.toString(),
          status: "confirmed",
        },
      });

      return receipt.transactionHash;
    } catch (error) {
      console.error("Blockchain update status error:", error);
      throw new Error("Failed to update status on blockchain");
    }
  }

  /**
   * Confirm delivery on blockchain
   */
  async confirmDelivery(
    shipmentId: number,
    signature: string,
    trackingNumber: string,
  ): Promise<string> {
    try {
      console.log(
        `✅ Confirming delivery for ${trackingNumber} on blockchain...`,
      );

      const timestamp = Math.floor(Date.now() / 1000);
      const tx = await this.contract.confirmDelivery(
        shipmentId,
        signature,
        timestamp,
      );
      const receipt = await tx.wait();

      console.log(
        `✅ Delivery confirmed on blockchain: ${receipt.transactionHash}`,
      );

      await prisma.blockchainTransaction.create({
        data: {
          txHash: receipt.transactionHash,
          blockNumber: receipt.blockNumber,
          type: "DELIVERY_CONFIRMED",
          trackingNumber,
          gasUsed: receipt.gasUsed.toString(),
          status: "confirmed",
        },
      });

      return receipt.transactionHash;
    } catch (error) {
      console.error("Blockchain confirm delivery error:", error);
      throw new Error("Failed to confirm delivery on blockchain");
    }
  }

  /**
   * Get shipment from blockchain
   */
  async getShipment(shipmentId: number): Promise<any> {
    try {
      const shipment = await this.contract.getShipment(shipmentId);

      return {
        trackingNumber: shipment.trackingNumber,
        origin: shipment.origin,
        destination: shipment.destination,
        weight: shipment.weight.toNumber(),
        status: shipment.status,
        createdAt: new Date(shipment.createdAt.toNumber() * 1000),
        deliveredAt:
          shipment.deliveredAt.toNumber() > 0
            ? new Date(shipment.deliveredAt.toNumber() * 1000)
            : null,
        signature: shipment.signature,
      };
    } catch (error) {
      console.error("Blockchain get shipment error:", error);
      throw new Error("Failed to get shipment from blockchain");
    }
  }

  /**
   * Verify transaction
   */
  async verifyTransaction(
    txHash: string,
  ): Promise<{ verified: boolean; details: any }> {
    try {
      const receipt = await this.provider.getTransactionReceipt(txHash);

      if (!receipt) {
        return { verified: false, details: null };
      }

      const block = await this.provider.getBlock(receipt.blockNumber);

      return {
        verified: receipt.status === 1,
        details: {
          txHash: receipt.transactionHash,
          blockNumber: receipt.blockNumber,
          blockHash: receipt.blockHash,
          timestamp: new Date(block.timestamp * 1000),
          gasUsed: receipt.gasUsed.toString(),
          confirmations: receipt.confirmations,
        },
      };
    } catch (error) {
      console.error("Blockchain verify transaction error:", error);
      return { verified: false, details: null };
    }
  }

  /**
   * Get gas price estimate
   */
  async estimateGas(
    operation: "create" | "update" | "confirm",
  ): Promise<{ gasLimit: string; gasPrice: string; estimatedCost: string }> {
    try {
      const gasPrice = await this.provider.getGasPrice();

      let gasLimit: ethers.BigNumber;
      switch (operation) {
        case "create":
          gasLimit = ethers.BigNumber.from("150000");
          break;
        case "update":
          gasLimit = ethers.BigNumber.from("100000");
          break;
        case "confirm":
          gasLimit = ethers.BigNumber.from("120000");
          break;
        default:
          gasLimit = ethers.BigNumber.from("100000");
      }

      const estimatedCost = gasLimit.mul(gasPrice);

      return {
        gasLimit: gasLimit.toString(),
        gasPrice: ethers.utils.formatUnits(gasPrice, "gwei") + " gwei",
        estimatedCost: ethers.utils.formatEther(estimatedCost) + " MATIC",
      };
    } catch (error) {
      console.error("Gas estimation error:", error);
      throw new Error("Failed to estimate gas");
    }
  }

  /**
   * Listen to blockchain events
   */
  startEventListener(): void {
    this.contract.on(
      "ShipmentCreated",
      (shipmentId, trackingNumber, customer, event) => {
        console.log(
          `🔔 Blockchain event: Shipment created ${trackingNumber} (ID: ${shipmentId})`,
        );
      },
    );

    this.contract.on(
      "ShipmentUpdated",
      (shipmentId, status, timestamp, event) => {
        console.log(
          `🔔 Blockchain event: Shipment ${shipmentId} status updated to ${status}`,
        );
      },
    );

    this.contract.on(
      "ShipmentDelivered",
      (shipmentId, signature, timestamp, event) => {
        console.log(`🔔 Blockchain event: Shipment ${shipmentId} delivered`);
      },
    );
  }

  /**
   * Stop event listener
   */
  stopEventListener(): void {
    this.contract.removeAllListeners();
  }
}

// Export singleton
export const blockchainManager = new BlockchainManager();

/**
 * Smart Contract (Solidity):
 *
 * // SPDX-License-Identifier: MIT
 * pragma solidity ^0.8.0;
 *
 * contract ShipmentRegistry {
 *     struct Shipment {
 *         string trackingNumber;
 *         string origin;
 *         string destination;
 *         uint256 weight;
 *         string status;
 *         uint256 createdAt;
 *         uint256 deliveredAt;
 *         string signature;
 *         address customer;
 *     }
 *
 *     mapping(uint256 => Shipment) public shipments;
 *     uint256 public shipmentCount;
 *
 *     event ShipmentCreated(uint256 indexed shipmentId, string trackingNumber, address indexed customer);
 *     event ShipmentUpdated(uint256 indexed shipmentId, string status, uint256 timestamp);
 *     event ShipmentDelivered(uint256 indexed shipmentId, string signature, uint256 timestamp);
 *
 *     function createShipment(
 *         string memory trackingNumber,
 *         string memory origin,
 *         string memory destination,
 *         uint256 weight
 *     ) public returns (uint256) {
 *         shipmentCount++;
 *
 *         shipments[shipmentCount] = Shipment({
 *             trackingNumber: trackingNumber,
 *             origin: origin,
 *             destination: destination,
 *             weight: weight,
 *             status: "PENDING",
 *             createdAt: block.timestamp,
 *             deliveredAt: 0,
 *             signature: "",
 *             customer: msg.sender
 *         });
 *
 *         emit ShipmentCreated(shipmentCount, trackingNumber, msg.sender);
 *         return shipmentCount;
 *     }
 *
 *     function updateShipmentStatus(
 *         uint256 shipmentId,
 *         string memory status,
 *         uint256 timestamp
 *     ) public {
 *         require(shipmentId <= shipmentCount, "Shipment does not exist");
 *
 *         shipments[shipmentId].status = status;
 *
 *         emit ShipmentUpdated(shipmentId, status, timestamp);
 *     }
 *
 *     function confirmDelivery(
 *         uint256 shipmentId,
 *         string memory signature,
 *         uint256 timestamp
 *     ) public {
 *         require(shipmentId <= shipmentCount, "Shipment does not exist");
 *
 *         shipments[shipmentId].status = "DELIVERED";
 *         shipments[shipmentId].deliveredAt = timestamp;
 *         shipments[shipmentId].signature = signature;
 *
 *         emit ShipmentDelivered(shipmentId, signature, timestamp);
 *     }
 *
 *     function getShipment(uint256 shipmentId) public view returns (Shipment memory) {
 *         require(shipmentId <= shipmentCount, "Shipment does not exist");
 *         return shipments[shipmentId];
 *     }
 * }
 *
 * Usage:
 *
 * // Create shipment on blockchain
 * const { txHash, shipmentId } = await blockchainManager.createShipment({
 *   trackingNumber: 'INF-2024-001',
 *   origin: 'New York, NY',
 *   destination: 'Los Angeles, CA',
 *   weight: 5000,
 * });
 *
 * // Update status
 * await blockchainManager.updateShipmentStatus(shipmentId, 'IN_TRANSIT', 'INF-2024-001');
 *
 * // Confirm delivery
 * await blockchainManager.confirmDelivery(shipmentId, 'signature-data', 'INF-2024-001');
 *
 * // Verify transaction
 * const { verified, details } = await blockchainManager.verifyTransaction(txHash);
 *
 * // Get shipment from blockchain
 * const shipment = await blockchainManager.getShipment(shipmentId);
 *
 * Database schema:
 *
 * model BlockchainTransaction {
 *   id             String   @id @default(uuid())
 *   txHash         String   @unique
 *   blockNumber    Int
 *   type           String
 *   trackingNumber String
 *   gasUsed        String
 *   status         String
 *   createdAt      DateTime @default(now())
 * }
 *
 * Benefits:
 * - Immutable audit trail
 * - Tamper-proof records
 * - Transparent proof of delivery
 * - Cross-organization trust
 * - Smart contract automation
 * - Decentralized verification
 * - Compliance ready
 */
