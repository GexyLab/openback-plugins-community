<?php

/**
 * A read-only field showing an address to register on the pool's `web` app: the redirect URI (default) or the
 * site's root (attribute kind="root", the default post-logout redirect URI).
 *
 * @copyright  (C) 2026 GexyLab and the OpenBack contributors
 * @license    GPL-2.0-or-later
 */

declare(strict_types=1);

namespace GexyLab\Plugin\System\OpenBackAppAuth\Field;

\defined('_JEXEC') or die;

use Joomla\CMS\Form\FormField;
use Joomla\CMS\Uri\Uri;

final class RedirecturiField extends FormField
{
    protected $type = 'Redirecturi';

    protected function getInput()
    {
        $kind  = (string) ($this->element['kind'] ?? 'callback');
        $value = $kind === 'root'
            ? Uri::root()
            : Uri::root() . 'index.php?option=com_ajax&group=system&plugin=openbackappauth&format=raw&task=callback';
        return '<input type="text" class="form-control" readonly value="' . htmlspecialchars($value, ENT_QUOTES, 'UTF-8') . '"'
            . ' id="' . htmlspecialchars((string) $this->id, ENT_QUOTES, 'UTF-8') . '" onfocus="this.select()">';
    }
}
