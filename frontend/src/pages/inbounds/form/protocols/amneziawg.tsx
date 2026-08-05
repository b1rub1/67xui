import { useTranslation } from 'react-i18next';
import { Button, Divider, Form, Input, InputNumber, Space, Tooltip } from 'antd';
import { ReloadOutlined, InfoCircleOutlined } from '@ant-design/icons';

import { FormField } from '@/components/form/rhf';

interface AWGFieldsProps {
  awgPubKey: string;
  regenInboundAWG: () => void;
  regenAWGParams: () => void;
}

export default function AmneziaWGFields({ awgPubKey, regenInboundAWG, regenAWGParams }: AWGFieldsProps) {
  const { t } = useTranslation();

  return (
    <>
      {/* Server keypair */}
      <Form.Item label={t('pages.xray.amneziawg.secretKey', 'Server Private Key')}>
        <Space.Compact block>
          <FormField name={['settings', 'secretKey']} noStyle>
            <Input style={{ width: 'calc(100% - 32px)' }} />
          </FormField>
          <Button aria-label={t('regenerate')} icon={<ReloadOutlined />} onClick={regenInboundAWG} />
        </Space.Compact>
      </Form.Item>

      <Form.Item label={t('pages.xray.amneziawg.publicKey', 'Server Public Key')}>
        <Input value={awgPubKey} disabled />
      </Form.Item>

      <FormField name={['settings', 'address']} label={t('pages.xray.amneziawg.address', 'Tunnel Address')}>
        <Input placeholder="10.66.0.1/16" />
      </FormField>

      <FormField name={['settings', 'mtu']} label="MTU">
        <InputNumber min={576} max={9000} placeholder="1420" style={{ width: '100%' }} />
      </FormField>

      <FormField name={['settings', 'dns']} label="DNS">
        <Input placeholder="1.1.1.1" />
      </FormField>

      <Divider orientation="left" orientationMargin={0}>
        AmneziaWG 2.0{' '}
        <Tooltip title={t('pages.xray.amneziawg.paramsHint', 'Obfuscation parameters. Click Regenerate to get secure random values.')}>
          <InfoCircleOutlined style={{ fontSize: 12 }} />
        </Tooltip>
        <Button
          size="small"
          icon={<ReloadOutlined />}
          onClick={regenAWGParams}
          style={{ marginLeft: 8 }}
        >
          {t('pages.xray.amneziawg.regenParams', 'Regenerate')}
        </Button>
      </Divider>

      {/* Junk packets */}
      <Form.Item label="Jc / Jmin / Jmax" tooltip={t('pages.xray.amneziawg.junkHint', 'Junk packets sent before handshake (count, min size, max size)')}>
        <Space>
          <FormField name={['settings', 'params', 'jc']} noStyle>
            <InputNumber min={1} max={128} placeholder="Jc" style={{ width: 80 }} />
          </FormField>
          <FormField name={['settings', 'params', 'jmin']} noStyle>
            <InputNumber min={40} max={1000} placeholder="Jmin" style={{ width: 90 }} />
          </FormField>
          <FormField name={['settings', 'params', 'jmax']} noStyle>
            <InputNumber min={40} max={1280} placeholder="Jmax" style={{ width: 90 }} />
          </FormField>
        </Space>
      </Form.Item>

      {/* Message paddings */}
      <Form.Item label="S1 / S2 / S3 / S4" tooltip={t('pages.xray.amneziawg.paddingHint', 'Extra padding bytes for handshake init, response, cookie reply, transport packets')}>
        <Space>
          <FormField name={['settings', 'params', 's1']} noStyle>
            <InputNumber min={15} max={150} placeholder="S1" style={{ width: 70 }} />
          </FormField>
          <FormField name={['settings', 'params', 's2']} noStyle>
            <InputNumber min={15} max={150} placeholder="S2" style={{ width: 70 }} />
          </FormField>
          <FormField name={['settings', 'params', 's3']} noStyle>
            <InputNumber min={5} max={40} placeholder="S3" style={{ width: 70 }} />
          </FormField>
          <FormField name={['settings', 'params', 's4']} noStyle>
            <InputNumber min={1} max={32} placeholder="S4" style={{ width: 70 }} />
          </FormField>
        </Space>
      </Form.Item>

      {/* Magic headers */}
      <Form.Item label="H1 / H2 / H3 / H4" tooltip={t('pages.xray.amneziawg.headersHint', 'Random values replacing standard WireGuard message type fields')}>
        <Space wrap>
          <FormField name={['settings', 'params', 'h1']} noStyle>
            <InputNumber min={5} placeholder="H1" style={{ width: 110 }} />
          </FormField>
          <FormField name={['settings', 'params', 'h2']} noStyle>
            <InputNumber min={5} placeholder="H2" style={{ width: 110 }} />
          </FormField>
          <FormField name={['settings', 'params', 'h3']} noStyle>
            <InputNumber min={5} placeholder="H3" style={{ width: 110 }} />
          </FormField>
          <FormField name={['settings', 'params', 'h4']} noStyle>
            <InputNumber min={5} placeholder="H4" style={{ width: 110 }} />
          </FormField>
        </Space>
      </Form.Item>

      {/* Init chain (AWG 2.0) */}
      <Form.Item label="I1–I5" tooltip={t('pages.xray.amneziawg.initChainHint', 'Init packet chain segment descriptors (AWG 2.0). Format: <r N> for N random bytes.')}>
        <Space direction="vertical" style={{ width: '100%' }}>
          {(['i1', 'i2', 'i3', 'i4', 'i5'] as const).map((key) => (
            <FormField key={key} name={['settings', 'params', key]} noStyle>
              <Input placeholder={`${key.toUpperCase()}: <r 40>`} />
            </FormField>
          ))}
        </Space>
      </Form.Item>
    </>
  );
}
