import { z } from 'zod';

export const AWGParamsSchema = z.object({
  jc:   z.number().int().min(1).max(128).optional(),
  jmin: z.number().int().min(40).max(1000).optional(),
  jmax: z.number().int().min(40).max(1280).optional(),
  s1:   z.number().int().min(15).max(150).optional(),
  s2:   z.number().int().min(15).max(150).optional(),
  s3:   z.number().int().min(5).max(40).optional(),
  s4:   z.number().int().min(1).max(32).optional(),
  h1:   z.number().int().min(5).optional(),
  h2:   z.number().int().min(5).optional(),
  h3:   z.number().int().min(5).optional(),
  h4:   z.number().int().min(5).optional(),
  i1:   z.string().optional(),
  i2:   z.string().optional(),
  i3:   z.string().optional(),
  i4:   z.string().optional(),
  i5:   z.string().optional(),
}).default({});
export type AWGParams = z.infer<typeof AWGParamsSchema>;

export const AWGClientSchema = z.object({
  publicKey:  z.string(),
  allowedIPs: z.string().default(''),
  email:      z.string().default(''),
  enable:     z.boolean().default(true),
}).passthrough();
export type AWGClient = z.infer<typeof AWGClientSchema>;

export const AmneziaWGInboundSettingsSchema = z.object({
  secretKey: z.string().default(''),
  address:   z.string().default('10.66.0.1/24'),
  mtu:       z.number().int().min(576).max(9000).default(1420),
  dns:       z.string().default('1.1.1.1'),
  params:    AWGParamsSchema,
  clients:   z.array(AWGClientSchema).default([]),
}).passthrough();
export type AmneziaWGInboundSettings = z.infer<typeof AmneziaWGInboundSettingsSchema>;
