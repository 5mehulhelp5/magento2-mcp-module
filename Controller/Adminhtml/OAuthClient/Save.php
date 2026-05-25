<?php
/**
 * @author    Magebit <info@magebit.com>
 * @copyright Copyright (c) Magebit, Ltd. (https://magebit.com)
 * @license   MIT
 */
declare(strict_types=1);

namespace Magebit\Mcp\Controller\Adminhtml\OAuthClient;

use InvalidArgumentException;
use Magebit\Mcp\Api\ToolRegistryInterface;
use Magebit\Mcp\Helper\Acl\ToolResourceTree;
use Magebit\Mcp\Model\OAuth\AuthMode;
use Magebit\Mcp\Model\OAuth\Client;
use Magebit\Mcp\Model\OAuth\ClientCredentialIssuer;
use Magebit\Mcp\Model\OAuth\ClientRepository;
use Magebit\Mcp\Model\Adminhtml\FormDataPersistence;
use Magento\Backend\App\Action;
use Magento\Backend\App\Action\Context;
use Magento\Backend\Model\View\Result\Page;
use Magento\Backend\Model\View\Result\Redirect;
use Magento\Framework\App\Action\HttpPostActionInterface;
use Magento\Framework\App\Request\Http as HttpRequest;
use Magento\Framework\Controller\ResultFactory;
use Magento\Framework\Controller\ResultInterface;
use Magento\Framework\Exception\NoSuchEntityException;
use Magento\Framework\View\Element\AbstractBlock;
use Throwable;

/**
 * POST `magebit_mcp/oauthclient/save` — create + edit. On create the freshly minted
 * plaintext secret is rendered inline on the response so it is never written to
 * session storage. On edit only `name`, `redirect_uris`, and `allowed_tools` are
 * mutable — secret rotation = delete + create.
 */
class Save extends Action implements HttpPostActionInterface
{
    public const ADMIN_RESOURCE = 'Magebit_Mcp::mcp_oauth_clients';

    /**
     * @param Context $context
     * @param ClientCredentialIssuer $issuer
     * @param ClientRepository $clientRepository
     * @param ToolRegistryInterface $toolRegistry
     * @param FormDataPersistence $formDataPersistence
     */
    public function __construct(
        Context $context,
        private readonly ClientCredentialIssuer $issuer,
        private readonly ClientRepository $clientRepository,
        private readonly ToolRegistryInterface $toolRegistry,
        private readonly FormDataPersistence $formDataPersistence
    ) {
        parent::__construct($context);
    }

    /**
     * @return ResultInterface
     */
    public function execute(): ResultInterface
    {
        /** @var Redirect $redirect */
        $redirect = $this->resultFactory->create(ResultFactory::TYPE_REDIRECT);

        /** @var HttpRequest $request */
        $request = $this->getRequest();
        $rawAny = $request->getPostValue();
        if (!is_array($rawAny) || $rawAny === []) {
            $this->messageManager->addErrorMessage((string) __('Missing form payload.'));
            return $redirect->setPath('*/*/index');
        }
        // Narrow to string-keyed; numeric-keyed top-level entries from getPostValue() never
        // map to form fields and are simply dropped.
        $raw = [];
        foreach ($rawAny as $key => $value) {
            if (is_string($key)) {
                $raw[$key] = $value;
            }
        }

        $name = $this->extractName($raw);
        $redirectUris = $this->extractRedirectUris($raw);
        $allowedTools = $this->extractAllowedTools($raw);
        $auth = $this->extractAuthorizationOptions($raw);

        $idRaw = $raw['id'] ?? 0;
        $editingId = is_scalar($idRaw) ? (int) $idRaw : 0;

        $authError = $this->validateAuthorizationOptions($auth);

        if ($name === '' || $redirectUris === [] || $allowedTools === [] || $authError !== null) {
            $this->preserveFormData($raw, $allowedTools);
            if ($name === '') {
                $this->messageManager->addErrorMessage((string) __('Name is required.'));
            }
            if ($redirectUris === []) {
                $this->messageManager->addErrorMessage((string) __('At least one redirect URI is required.'));
            }
            if ($allowedTools === []) {
                $this->messageManager->addErrorMessage((string) __('Pick at least one tool this client may request.'));
            }
            if ($authError !== null) {
                $this->messageManager->addErrorMessage($authError);
            }
            return $editingId > 0
                ? $redirect->setPath('*/*/edit', ['id' => $editingId])
                : $redirect->setPath('*/*/new');
        }

        if ($editingId > 0) {
            return $this->handleUpdate($redirect, $editingId, $name, $redirectUris, $allowedTools, $auth, $raw);
        }

        return $this->handleCreate($redirect, $name, $redirectUris, $allowedTools, $auth, $raw);
    }

    /**
     * @param Redirect $redirect
     * @param int $editingId
     * @param string $name
     * @param array<int, string> $redirectUris
     * @param array<int, string> $allowedTools
     * @param array{
     *     mode: AuthMode,
     *     service_admin_user_id: ?int,
     *     allowed_admin_user_ids: array<int, int>,
     *     allowed_admin_role_ids: array<int, int>,
     *     disabled: bool
     * } $auth
     * @param array<string, mixed> $raw
     * @return Redirect
     */
    private function handleUpdate(
        Redirect $redirect,
        int $editingId,
        string $name,
        array $redirectUris,
        array $allowedTools,
        array $auth,
        array $raw
    ): Redirect {
        try {
            $client = $this->clientRepository->getById($editingId);
        } catch (NoSuchEntityException) {
            $this->messageManager->addErrorMessage(
                (string) __('OAuth client #%1 no longer exists.', $editingId)
            );
            return $redirect->setPath('*/*/index');
        }

        try {
            $client->setName($name);
            $client->setRedirectUris($redirectUris);
            $client->setAllowedTools($allowedTools);
            $this->applyAuthorizationOptions($client, $auth);
            $this->clientRepository->save($client);
        } catch (Throwable $e) {
            $this->preserveFormData($raw, $allowedTools);
            $this->messageManager->addErrorMessage(
                (string) __('Failed to update OAuth client: %1', $e->getMessage())
            );
            return $redirect->setPath('*/*/edit', ['id' => $editingId]);
        }

        $this->messageManager->addSuccessMessage(
            (string) __('OAuth client "%1" updated.', $name)
        );
        return $redirect->setPath('*/*/index');
    }

    /**
     * @param Redirect $redirect
     * @param string $name
     * @param array<int, string> $redirectUris
     * @param array<int, string> $allowedTools
     * @param array{
     *     mode: AuthMode,
     *     service_admin_user_id: ?int,
     *     allowed_admin_user_ids: array<int, int>,
     *     allowed_admin_role_ids: array<int, int>,
     *     disabled: bool
     * } $auth
     * @param array<string, mixed> $raw
     * @return ResultInterface
     */
    private function handleCreate(
        Redirect $redirect,
        string $name,
        array $redirectUris,
        array $allowedTools,
        array $auth,
        array $raw
    ): ResultInterface {
        try {
            $issued = $this->issuer->issue($name, $redirectUris, $allowedTools);
            // Apply the new authorization options as a second save — keeps the
            // issuer signature stable and limits the blast radius of a future
            // schema change to this controller.
            $this->applyAuthorizationOptions($issued['client'], $auth);
            $this->clientRepository->save($issued['client']);
        } catch (InvalidArgumentException $e) {
            $this->preserveFormData($raw, $allowedTools);
            $this->messageManager->addErrorMessage($e->getMessage());
            return $redirect->setPath('*/*/new');
        } catch (Throwable $e) {
            $this->preserveFormData($raw, $allowedTools);
            $this->messageManager->addErrorMessage(
                (string) __('Failed to create OAuth client: %1', $e->getMessage())
            );
            return $redirect->setPath('*/*/new');
        }

        return $this->renderCredentialsPage($name, $issued['client_id'], $issued['client_secret']);
    }

    /**
     * @param string $name
     * @param string $clientId
     * @param string $clientSecret
     * @return Page
     */
    private function renderCredentialsPage(string $name, string $clientId, string $clientSecret): Page
    {
        /** @var Page $page */
        $page = $this->resultFactory->create(ResultFactory::TYPE_PAGE);
        $page->setActiveMenu('Magebit_Mcp::mcp_oauth_clients');
        $page->getConfig()->getTitle()->prepend((string) __('OAuth Client Created'));
        // No-store so an intermediate proxy / browser-back-forward cache can't replay the
        // credentials; the secret should never live anywhere except the operator's clipboard.
        $page->setHeader('Cache-Control', 'no-store, no-cache, must-revalidate', true);
        $page->setHeader('Pragma', 'no-cache', true);

        $block = $page->getLayout()->getBlock('mcp.oauthclient.created');
        if ($block instanceof AbstractBlock) {
            $block->setData('name', $name);
            $block->setData('client_id', $clientId);
            $block->setData('client_secret', $clientSecret);
        }
        return $page;
    }

    /**
     * @param array<string, mixed> $raw
     */
    private function extractName(array $raw): string
    {
        $value = $raw['name'] ?? '';
        if (!is_scalar($value)) {
            return '';
        }
        $value = trim((string) $value);
        if (strlen($value) > 128) {
            $value = substr($value, 0, 128);
        }
        return $value;
    }

    /**
     * @param array<string, mixed> $raw
     * @return array<int, string>
     */
    private function extractRedirectUris(array $raw): array
    {
        $value = $raw['redirect_uris'] ?? '';
        if (!is_scalar($value)) {
            return [];
        }
        $lines = preg_split('/\r\n|\r|\n/', (string) $value);
        if ($lines === false) {
            return [];
        }
        $out = [];
        foreach ($lines as $line) {
            $trimmed = trim($line);
            if ($trimmed !== '') {
                $out[] = $trimmed;
            }
        }
        return array_values(array_unique($out));
    }

    /**
     * @param array<string, mixed> $raw
     * @return array<int, string>
     */
    private function extractAllowedTools(array $raw): array
    {
        $resourceIds = $raw['resource'] ?? [];
        if (!is_array($resourceIds) || $resourceIds === []) {
            return [];
        }

        $toolByAclId = [];
        foreach ($this->toolRegistry->all() as $tool) {
            $toolByAclId[$tool->getAclResource()] = $tool->getName();
        }

        $names = [];
        $seen = [];
        foreach ($resourceIds as $resourceId) {
            if (!is_string($resourceId)) {
                continue;
            }
            $rid = trim($resourceId);
            if ($rid === '') {
                continue;
            }
            if ($rid === ToolResourceTree::ROOT_RESOURCE_ID || str_starts_with($rid, 'mcp_group_')) {
                continue;
            }
            $name = $toolByAclId[$rid] ?? null;
            if ($name === null || isset($seen[$name])) {
                continue;
            }
            $seen[$name] = true;
            $names[] = $name;
        }
        return $names;
    }

    /**
     * @param array<string, mixed> $raw
     * @param array<int, string> $allowedTools
     */
    private function preserveFormData(array $raw, array $allowedTools): void
    {
        $this->formDataPersistence->set([
            'name' => $raw['name'] ?? '',
            'redirect_uris' => $raw['redirect_uris'] ?? '',
            'allowed_tools' => $allowedTools,
            'auth_mode' => $raw['auth_mode'] ?? AuthMode::PERSONAL->value,
            'service_admin_user_id' => $raw['service_admin_user_id'] ?? '',
            'allowed_admin_user_ids' => is_array($raw['allowed_admin_user_ids'] ?? null)
                ? $raw['allowed_admin_user_ids']
                : [],
            'allowed_admin_role_ids' => is_array($raw['allowed_admin_role_ids'] ?? null)
                ? $raw['allowed_admin_role_ids']
                : [],
            'disabled' => $raw['disabled'] ?? '0',
        ]);
    }

    /**
     * @param array<string, mixed> $raw
     * @return array{
     *     mode: AuthMode,
     *     service_admin_user_id: ?int,
     *     allowed_admin_user_ids: array<int, int>,
     *     allowed_admin_role_ids: array<int, int>,
     *     disabled: bool
     * }
     */
    private function extractAuthorizationOptions(array $raw): array
    {
        $modeRaw = $raw['auth_mode'] ?? AuthMode::PERSONAL->value;
        $mode = AuthMode::tryFrom(is_string($modeRaw) ? $modeRaw : '') ?? AuthMode::PERSONAL;

        $serviceAdminRaw = $raw['service_admin_user_id'] ?? null;
        $serviceAdmin = is_scalar($serviceAdminRaw) && (int) $serviceAdminRaw > 0
            ? (int) $serviceAdminRaw
            : null;

        $disabledRaw = $raw['disabled'] ?? '0';
        $disabled = is_scalar($disabledRaw) && (int) $disabledRaw === 1;

        return [
            'mode' => $mode,
            'service_admin_user_id' => $serviceAdmin,
            'allowed_admin_user_ids' => $this->extractIntList($raw['allowed_admin_user_ids'] ?? null),
            'allowed_admin_role_ids' => $this->extractIntList($raw['allowed_admin_role_ids'] ?? null),
            'disabled' => $disabled,
        ];
    }

    /**
     * @param mixed $value
     * @return array<int, int>
     */
    private function extractIntList(mixed $value): array
    {
        if (!is_array($value)) {
            return [];
        }
        $out = [];
        $seen = [];
        foreach ($value as $item) {
            if (!is_scalar($item)) {
                continue;
            }
            $int = (int) $item;
            if ($int <= 0 || isset($seen[$int])) {
                continue;
            }
            $seen[$int] = true;
            $out[] = $int;
        }
        return $out;
    }

    /**
     * @param array{
     *     mode: AuthMode,
     *     service_admin_user_id: ?int,
     *     allowed_admin_user_ids: array<int, int>,
     *     allowed_admin_role_ids: array<int, int>,
     *     disabled: bool
     * } $auth
     * @return string|null Error string on misconfiguration, null on success.
     */
    private function validateAuthorizationOptions(array $auth): ?string
    {
        if ($auth['mode'] === AuthMode::SHARED && $auth['service_admin_user_id'] === null) {
            return (string) __(
                'Shared mode requires a Service Admin User. Pick the admin every issued token should be'
                . ' bound to, or switch to Personal mode.'
            );
        }
        return null;
    }

    /**
     * @param Client $client
     * @param array{
     *     mode: AuthMode,
     *     service_admin_user_id: ?int,
     *     allowed_admin_user_ids: array<int, int>,
     *     allowed_admin_role_ids: array<int, int>,
     *     disabled: bool
     * } $auth
     */
    private function applyAuthorizationOptions(Client $client, array $auth): void
    {
        $client->setAuthMode($auth['mode']);
        if ($auth['mode'] === AuthMode::SHARED) {
            $client->setServiceAdminUserId($auth['service_admin_user_id']);
            // Whitelists only apply in personal mode — clear them to avoid stale UI state
            // leaking back if the client is later switched back to personal.
            $client->setAllowedAdminUserIds([]);
            $client->setAllowedAdminRoleIds([]);
        } else {
            $client->setServiceAdminUserId(null);
            $client->setAllowedAdminUserIds($auth['allowed_admin_user_ids']);
            $client->setAllowedAdminRoleIds($auth['allowed_admin_role_ids']);
        }
        $client->setDisabled($auth['disabled']);
    }
}
